use std::io;

use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice, TcpHeader, Ipv4Header, ip_number};

pub enum State{
    Closed,
    Listen,
    SynRcvd,
    //Estab,
}


pub struct Connection{
    state:State,
    send : SendSequenceSpace,
    recv : RecvSequenceSpace,
}

struct SendSequenceSpace {
    // send unacknowledge
    una : u32,
    // send next
    nxt : u32,
    // window size
    wnd : u16,
    //uregent pointer
    up : bool,
    // segment sequence number used for last window update
    wl1 : u32,
    // segment acknowledgment number used for last window update
    wl2 : u32,
    // initial send sequence number
    iss : u32,

}

struct RecvSequenceSpace {
    // receive next
    nxt : u32,
    // receive window
    wnd : u16,
    // receive urgent pointer
    up : bool,
    // initial receive sequence number
    irs : u32,
}


impl Connection{
    pub fn accept <'a>(
        nic: &mut tun_tap::Iface,
        iph:Ipv4HeaderSlice<'a>,
        tcph:TcpHeaderSlice<'a>,
        data:&[u8]
    )->io::Result<Option<Self>>{
        let mut buf = [0u8;1500];
        if !tcph.syn() {
            //Only expected Syn
            return Ok(None)
        }
        // Need to establish connection
        // cook a TCP header
        
        // keep track of sender info
        let iss = 0;
        let mut c = Connection{
            state: State::SynRcvd,
            send : SendSequenceSpace {
                iss,
                una : iss,
                nxt : iss + 1,
                wnd : 10,
                up : false,

                wl1 : 0,
                wl2 : 0
            },
            recv : RecvSequenceSpace {
                irs : tcph.sequence_number(),
                nxt  : tcph.sequence_number() + 1,
                wnd  : tcph.window_size(),
                up : false ,
            }
        
        };
    

        //decide on the stuff we are sending them


        let mut syn_ack = 
            TcpHeader::new(tcph.destination_port(),
            tcph.source_port(),
            c.send.iss,
            c.send.wnd);
        syn_ack.acknowledgment_number = c.recv.nxt;
        
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
                let unwritten = {
                    let mut unwritten = &mut buf[..];
                    h.write(&mut unwritten)?;
                    syn_ack.write(&mut unwritten)?;
                    unwritten.len()
                };
                nic.send(&buf[..unwritten])?;

            },
            Err(e)=>{
                eprintln!("Too long IPV4 header: {}",e);
                //Probably wrong but i don't know how to handle when too long
            }
        }
                          
        //Write out the header
        Ok(Some(c))   
    }
    
     pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph:Ipv4HeaderSlice<'a>,
        tcph:TcpHeaderSlice<'a>,
        data:&[u8]
    )->io::Result<()>{
        unimplemented!();
    }


}
