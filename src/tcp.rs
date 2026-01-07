use std::{cmp::Ordering, io, iter::StepBy};

use etherparse::{ip_number, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};

pub enum State {
    //Closed,
    //Listen,
    SynRcvd,
    Estab,
    FinWait1,
    Closing,
    TimeWait,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match self {
            State::SynRcvd => false, 
            State::Estab | State::FinWait1 | State::Closing | State::TimeWait => true,
        }
    }
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,
}

struct SendSequenceSpace {
    // send unacknowledge
    una: u32,
    // send next
    nxt: u32,
    // window size
    wnd: u16,
    //uregent pointer
    up: bool,
    // segment sequence number used for last window update
    wl1: u32,
    // segment acknowledgment number used for last window update
    wl2: u32,
    // initial send sequence number
    iss: u32,
}

struct RecvSequenceSpace {
    // receive next
    nxt: u32,
    // receive window
    wnd: u16,
    // receive urgent pointer
    up: bool,
    // initial receive sequence number
    irs: u32,
}

impl Connection {
    pub fn write(
        &mut self,
        nic: &mut tun_tap::Iface,
        payload: &[u8]
    ) -> io::Result<usize>{
        let mut buf = [0u8; 1500];
        self.tcp.sequence_number = self.send.nxt;
        self.tcp.acknowledgment_number = self.recv.nxt;

        let size = std::cmp::min(
            buf.len(), payload.len() + self.tcp.header_len() + self.ip.header_len()
        );

        self.ip.set_payload_len(size);

        // TODO: serialize TCP header and IP header to buffer and send via NIC
        // For now, just return the payload length
        
        use std::io::Write;
        let mut unwritten = &mut buf[..]; // Here unwritten is a mutable slice
        self.ip.write(&mut unwritten); // Now ipv4 header is written onto the buffer and write pointer
                                     // moves forward
        self.tcp.write(&mut unwritten); // Again TCP header is added and pointer moves forward
        let payload_bytes = unwritten.write(payload)?;                            // without overlapping
        let unwritten = unwritten.len();
        self.send.nxt = self.send.nxt.wrapping_add(payload_bytes as u32);

        if self.tcp.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin{
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.fin = false;
        }

        nic.send(&buf[..buf.len() - unwritten])?;

        Ok(payload_bytes)
    }

    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        iph: Ipv4HeaderSlice<'a>,
        tcph: TcpHeaderSlice<'a>,
        data: &[u8],
    ) -> io::Result<Option<Self>> {
        let mut buf = [0u8; 1500];
        if !tcph.syn() {
            //Only expected Syn
            return Ok(None);
        }
        // Need to establish connection
        // cook a TCP header

        // keep track of sender info
        let iss = 0;
        let wnd = 10;
        let mut c = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss + 1,
                wnd: wnd,
                up: false,

                wl1: 0,
                wl2: 0,
            },
            tcp: etherparse::TcpHeader::new(tcph.source_port(), tcph.destination_port(), iss, wnd),
            recv: RecvSequenceSpace {
                irs: tcph.sequence_number(),
                nxt: tcph.sequence_number() + 1,
                wnd: tcph.window_size(),
                up: false,
            },

            ip: match Ipv4Header::new(0, 64, ip_number::TCP, iph.destination(), iph.source()) {
                Ok(h) => {
                    // kernel calculates the checksum by itself

                    // syn_ack.checksum = syn_ack.calc_checksum_ipv4(&h, &[])
                    //     .expect("failed to set checksum");

                    h
                }
                Err(e) => {
                    eprintln!("Too long IPV4 header: {}", e);
                    panic!("Error while creating IPv4 header");
                    //Probably wrong but i don't know how to handle when too long
                }
            },
        };

        //decide on the stuff we are sending them

        c.tcp.syn = true;
        c.tcp.ack = true;
        c.write(nic, &[])?;

        Ok(Some(c)) // Return the connection
    }

    pub fn send_rst(
        &mut self,
        nic: &mut tun_tap::Iface,
    ) -> io::Result<()> {
        self.tcp.rst = true;
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.write(nic, &[])?;
        Ok(())
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: Ipv4HeaderSlice<'a>,
        tcph: TcpHeaderSlice<'a>,
        data: &[u8],
    ) -> io::Result<()> {
        // A new acknowledgment (called an "acceptable ack"), is one for which
        // the inequality below holds:
        // SND.UNA < SEG.ACK <= SND.NXT

        let ackn = tcph.acknowledgment_number();

        if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {

            // if we're not synchronized, return a RST
            if !self.state.is_synchronized() { 
                // self.tcp.sequence_number = tcph.acknowledgment_number();
                self.send_rst(nic);
                return Ok(());
            }
        }

        let seqn = tcph.sequence_number();
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        let mut slen = data.len() as u32;
        
        if tcph.fin() || tcph.syn() {
            slen += 1;
        }

        if slen == 0 {
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    return Ok(());
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                return Ok(());
            }
        } else {
            if self.recv.wnd == 0 {
                return Ok(());
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(
                    self.recv.nxt.wrapping_sub(1),
                    seqn + slen - 1,
                    wend,
                )
            {
                return Ok(());
            }
        }

        match self.state {
            State::SynRcvd => {
                //expect to get an ACK for our SYN
                if !tcph.ack() {
                    return Ok(());
                }
                //verify the acknowledgment number matches what we expect
                if ackn != self.send.nxt {
                    return Ok(());
                }

                
                self.state = State::Estab;
                println!("Connection established");

                 // terminate the connection for now
                self.tcp.fin = true;
                self.write(nic, &[])?;

                self.state = State::FinWait1;
                println!("Connection terminated - moving to FinWait1");
                return Ok(());
            }
            State::Estab => {
                unimplemented!();
            }
            State::FinWait1 => {
                if !tcph.fin() || !data.is_empty(){
                    // Not a FIN packet, ignore
                    unimplemented!()
                }
                // Handle FIN packet

                self.tcp.fin = false;
                self.write(nic, &[])?;
                self.state = State::TimeWait;
            }
            _ => {
                // Ignore other states for now
                println!("Ignoring packet in state: {}", stringify!(self.state));
            }
        }
        Ok(())
    }
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    match start.cmp(&x) {
        Ordering::Equal => false,
        Ordering::Less => {
            if end >= start && end <= x {
                return false;
            } else {
                return true;
            }
        }
        Ordering::Greater => {
            if end < start && end > x {
                return true;
            } else {
                return false;
            }
        }
    }
}
