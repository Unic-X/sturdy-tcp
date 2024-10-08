use std::{io, collections::HashMap};
use std::collections::hash_map::Entry;
use std::net::Ipv4Addr;
use etherparse::{ Ipv4HeaderSlice, IpNumber, TcpHeaderSlice};

mod tcp;

#[derive(Hash,Eq, PartialEq,Clone,Copy,Debug)]
struct Quad{
    src:(Ipv4Addr,u16),
    dst:(Ipv4Addr,u16)
}


fn main()->io::Result<()> {

    let mut connections :HashMap<Quad,tcp::Connection> = Default::default();

    let mut nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8;1504];
    loop{
        let nbytes = nic.recv(&mut buf[..])?;
        // let _eth_flags = u16::from_be_bytes([buf[0],buf[1]]);
        // let eth_proto = u16::from_be_bytes([buf[2],buf[3]]);
        // 

        // //not IPV4
        // if eth_proto!=0x800{
        //     continue;
        // }

        match Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
            Ok(iph) => {
                let src = iph.source_addr();
                let dst = iph.destination_addr();
                
                if iph.protocol() !=IpNumber::TCP {
                    //not TCP
                    continue;
                }
                
                match TcpHeaderSlice::from_slice(&buf[iph.slice().len()..nbytes]) {
                    Ok(tcph)=>{

                        let datai = iph.slice().len() + tcph.slice().len();
                        match connections.entry(Quad {
                            src: (src,tcph.source_port()),
                            dst: (dst,tcph.destination_port()) 
                        }){
                            Entry::Occupied(mut c)=> {
                                c.get_mut().on_packet(&mut nic,iph,tcph,&buf[datai..nbytes])?;
                            },
                            Entry::Vacant(mut e) => {
                                if let Some(c) = tcp::Connection::accept(&mut nic,
                                        iph,
                                        tcph, 
                                        &buf[datai..nbytes]
                                    )?{
                                    e.insert(c);
                                }
                            }
                        }                     
                    }
                    Err(e)=>{
                        eprintln!("Ignoring wierd TCP packet Err:{}",e);
                    }
                    
                }
               
            },
            Err(e) => {
                eprintln!("{}",e);
            }
            
        }
       
    }
    
}
