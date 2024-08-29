use std::{cmp::Ordering, io};

use etherparse::{ip_number, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};

pub enum State {
    //Closed,
    //Listen,
    SynRcvd,
    Estab,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header,
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
        let mut c = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss + 1,
                wnd: 10,
                up: false,

                wl1: 0,
                wl2: 0,
            },
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

        let mut syn_ack = TcpHeader::new(
            tcph.destination_port(),
            tcph.source_port(),
            c.send.iss,
            c.send.wnd,
        );
        syn_ack.acknowledgment_number = c.recv.nxt;

        syn_ack.syn = true;
        syn_ack.ack = true;
        c.ip.set_payload_len(syn_ack.header_len() + 0);

        let unwritten = {
            let mut unwritten = &mut buf[..]; // Here unwritten is a mutable slice
            c.ip.write(&mut unwritten)?; // Now ipv4 header is written onto the buffer and write pointer
                                         // moves forward
            syn_ack.write(&mut unwritten)?; // Again TCP header is added and pointer moves forward
                                            // without overlapping
            unwritten.len() // Return the written length i.e how much is written
        };

        nic.send(&buf[..unwritten])?; // Send written data to the ethernet

        //Write out the header
        Ok(Some(c)) // Return the connection
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
            return Ok(());
        }

        let seqn = tcph.sequence_number();
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        let mut slen = data.len() as u32;
        
        if tcph.fin() {
            slen +=1;
        }

        if tcph.syn() {
            slen +=1;
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
            }
            State::Estab => {
                unimplemented!()
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
