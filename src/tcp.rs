use std::io;

use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice, TcpHeader, Ipv4Header, ip_number};

pub enum State{
    Closed,
    Listen,
    //SynRcvd,
    //Estab,
}


pub struct Connection{
    state:State,
}

impl Default for Connection{
    fn default() -> Self {
        Connection {
            state: State::Listen, 
        }
    }
}


impl State{
    pub fn on_packet <'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph:Ipv4HeaderSlice<'a>,
        tcph:TcpHeaderSlice<'a>,
        data:&[u8]
    )->io::Result<usize>{
        let mut buf = [0u8;1500];
        match *self {
            State::Closed => {
                return Ok(0)
            },
            State::Listen => {
                if !tcph.syn() {
                    //Only expected Syn
                    return Ok(0)
                }
                // Need to establish connection
                // cook a TCP header
                let mut syn_ack = 
                    TcpHeader::new(tcph.destination_port(),tcph.source_port(),0,0);

                syn_ack.syn = true;
                syn_ack.ack = true;

                match Ipv4Header::new(
                    syn_ack.header_len_u16(),
                    64,
                    ip_number::TCP,
                    iph.destination(),
                    iph.source(),
                    
                ){
                    Ok(h)=>{
                        let mut unwritten = &mut buf[..];
                        h.write(&mut unwritten)?;
                        syn_ack.write(&mut unwritten)?;
                        nic.send(&buf[..unwritten.len()])

                    },
                    Err(e)=>{
                        eprintln!("Too long IPV4 header: {}",e);
                        //Probably wrong but i don't know how to handle when too long
                        //Only time 
                        Err(io::Error::new(io::ErrorKind::Other, "IPv4 header too large"))

                    }
                }
                                  
                //Write out the header
               
            },
          


        }
    }
}
