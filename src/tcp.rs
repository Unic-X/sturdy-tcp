use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};

pub struct State{
    
}


impl Default for State{
    fn default() -> Self {
        State {  }
    }
}


impl State{
    pub fn on_packet <'a>(
        &mut self,
        iph:Ipv4HeaderSlice<'a>,
        tcph:TcpHeaderSlice<'a>,
        data:&[u8]
    ){
        eprintln!("{}:{} -> {}:{} {}bytes of TCP  ",
            iph.source_addr(),
            tcph.source_port(),
            iph.destination_addr(),
            tcph.destination_port(),
            data.len(),
        );
    }
}
