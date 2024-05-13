
// Import necessary dependencies
extern crate pcap;
extern crate pnet;
use std::cell::RefCell;
use iced::subscription;
use iced::Subscription;
use iced::futures::channel::mpsc::Sender;
use pnet::packet::Packet;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use std::collections::HashMap;
use std::fmt;
use std::process::Command;
use std::str;
use if_addrs::get_if_addrs;
use regex::Regex;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::net::IpAddr;
use iced::{Application, Settings};
use iced::widget::text::Text;
use iced::Command as IcedCommand;
use iced::Element;
use iced::widget::Row;
use iced::widget::Column;


// Define the Process struct
#[derive(Clone, Hash, Eq, PartialEq)]
pub struct Process {
    id: u32,
    name: String,
}

impl Process {
    pub fn new(id: u32, name: &str) -> Self {
        Self {
            id,
            name: name.to_string(),
        }
    }


}
// Define the Packet struct
#[derive(Clone, Debug)]
pub struct Packets {
    sent_size: u32,
    received_size: u32,
    sent_number: u32,
    received_number: u32,
}
impl ToString for Packets {
    fn to_string(&self) -> String {
        format!(
            "Sent Size: {}, Received Size: {}, Sent Number: {}, Received Number: {}",
            self.sent_size, self.received_size, self.sent_number, self.received_number
        )
    }
}

impl Packets {
    pub fn new( sent_size: u32,
    received_size: u32,
    sent_number: u32,
    received_number: u32) -> Self {
        Self {
            sent_size,
            received_size,
            sent_number,
            received_number,
        }
    }
}

// Usage
struct App {
    data: HashMap<Process, Packets>,
    receiver: RefCell<Option<std::sync::mpsc::Receiver<Message>>>,
}
enum Message {
    NewData(HashMap<Process, Packets>),
    // other messages...
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Message::NewData(data) => {
                // If you can't print `data`, just print a placeholder
                f.debug_struct("NewData")
                 .field("data", &"Non-debuggable data")
                 .finish()
            },
            // handle other messages...
        }
    }
}

impl Application for App {
    type Executor = iced::executor::Default;
    type Message = Message;
    type Flags = UiFlags;
    type Theme= iced::Theme;
    // fn new(flags: UiFlags) -> (Self, Command<Message>) {
    //     let app = Ui {
    //         receiver: RefCell::new(Some(flags.receiver)),
    //         num: 0,
    //     };
    //     (app, Command::none())
    // }

    fn new(flags: UiFlags) -> (App, IcedCommand<Self::Message>) {
        (App { data: HashMap::new() , receiver:RefCell::new(Some(flags.receiver))}, IcedCommand::none())
    }

    fn title(&self) -> String {
        String::from("My Window")
    }

    fn update(&mut self, message: Self::Message) -> IcedCommand<Self::Message> {
        match message {
            Message::NewData(new_data) => {
                for (process, packets) in new_data {
                    self.data.entry(process).or_insert(packets);
                }            }
            // handle other messages...
        }
        IcedCommand::none()
    }

    fn view(& self) -> Element<Self::Message> {
        let mut table = Column::new();
        let row = Row::new()
        .push(Text::new("process".to_string()))
        .push(Text::new("data".to_string()));
        table = table.push(row);
        for (process, packets) in &self.data {
            let row = Row::new()
                .push(Text::new(process.name.clone())) // Assuming `name` is a String
                .push(Text::new(packets.to_string())); // Assuming `to_string` is implemented for `Packets`
            table = table.push(iced::widget::Rule::horizontal(10)); // Add a horizontal line
            table = table.push(row);
        }
        table.into()
    }
    fn subscription(&self) -> Subscription<Message> {
        subscription::unfold(
            "led changes",
            self.receiver.take(),
            move |mut receiver| async move {
                let process_packets = receiver.as_mut().unwrap().recv().unwrap();
                (process_packets, receiver)
            },
        )
    }
}
struct UiFlags {
    receiver:std::sync::mpsc::Receiver<Message>,
}
#[tokio::main] // Change this
async fn main() {
    // Spawn the GUI task

    let (sender, receiver) = std::sync::mpsc::channel();

    let network_task = tokio::spawn(async move{
    
    // Define the HashMap
    let process_packet_map: Arc<Mutex<HashMap<Process, Packets>>> = Arc::new(Mutex::new(HashMap::new()));
    let global_process_packet_map: Arc<Mutex<HashMap<Process, Packets>>> = Arc::new(Mutex::new(HashMap::new()));

    // In your main function, clone the Arc before moving it into the thread
    let map_for_thread = Arc::clone(&process_packet_map);
    let global_map_for_thread = Arc::clone(&global_process_packet_map);

    // Spawn a new thread for printing the live outputs
    let monitor_task = tokio::spawn(async move{
        loop {
            Monitor(&map_for_thread, &global_map_for_thread);
            thread::sleep(Duration::from_secs(1));
        }
    });

    // Choose the network interface for capturing. E.g., "eth0"
    let interface = "enp0s3";

    // Wait for both tasks to complete

    

    // Define the HashMap
    let process_packet_map: Arc<Mutex<HashMap<Process, Packets>>> = Arc::new(Mutex::new(HashMap::new()));
    let global_process_packet_map: Arc<Mutex<HashMap<Process, Packets>>> = Arc::new(Mutex::new(HashMap::new()));

    // In your main function, clone the Arc before moving it into the thread
    let map_for_thread = Arc::clone(&process_packet_map);
    let global_map_for_thread = Arc::clone(&global_process_packet_map);
    // Spawn a new thread for printing the live outputs
    
    thread::spawn(move || {
        loop {
            Monitor(&map_for_thread, &global_map_for_thread);
            thread::sleep(Duration::from_secs(1));
        }
    });

    
    // Choose the network interface for capturing. E.g., "eth0"
    let interface = "enp0s3";
    let if_addrs = get_if_addrs().unwrap();
    let interface_addr = if_addrs.iter()
        .find(|if_addr| if_addr.name == interface && !if_addr.addr.is_loopback())
        .expect("No such interface or interface does not have an IP address");

    let ip = interface_addr.addr.ip();

    // Open the capture for the given interface
    let mut cap = pcap::Capture::from_device(interface).unwrap()
        .promisc(true)  // Set the capture mode to promiscuous
        .snaplen(5000)  // Set the maximum bytes to capture per packet
        .open().unwrap();

    // Start capturing packets
    while let Ok(packet) = cap.next() {
        let packet_data = packet.data.to_vec();
        let ethernet = EthernetPacket::owned(packet_data).unwrap();
        let len = packet.data.len() as u32;
        let IPC = ip.clone();
        let map_for_thread = Arc::clone(&process_packet_map);
        let map_for_thread_clone = Arc::clone(&map_for_thread);
        thread::spawn(move || {
                Capture(&map_for_thread, ethernet, IPC, len);
        });
    
        let new_data = map_for_thread_clone.lock().unwrap().clone();
    sender.send(Message::NewData(new_data)).unwrap();
    use std::collections::HashMap;

    // Create a new HashMap
    let mut test_data: HashMap<Process, Packets> = HashMap::new();
    
    // Create instances of Process and Packets
let process = Process::new(10,"process1");
let packets = Packets::new(100, 200, 300, 400);

// Insert the process and packets into the HashMap
test_data.insert(process, packets);
    
    // Send test_data
//    sender.send(Message::NewData(test_data)).unwrap();
    }
    });
    App::run(Settings::with_flags(UiFlags { receiver }));
    let _ = tokio::try_join!(network_task);

}


fn Monitor(process_packet_map: &Arc<Mutex<HashMap<Process, Packets>>>, global_process_packet_map: &Arc<Mutex<HashMap<Process, Packets>>>) {
    // Lock the Mutex before accessing the HashMap
    {
    let mut map = process_packet_map.lock().unwrap();
    let mut global_map = global_process_packet_map.lock().unwrap();

    // Print the process packet map
    for (process, packet) in &*map {
        let pack = global_map.entry(process.clone())
            .or_insert(Packets { sent_size: 0, received_size: 0, sent_number: 0, received_number: 0 });
        pack.sent_size += packet.sent_size;
        pack.received_size += packet.received_size;
        pack.sent_number += packet.sent_number;
        pack.received_number += packet.received_number;                                
    }
    }
    {
    let map = process_packet_map.lock().unwrap();
    let global_map = global_process_packet_map.lock().unwrap();

    for (process, pack) in &*global_map {
        if let Some(packet) = map.get(&process) {
            println!("Process: {} ({})", process.name, process.id);
            println!("Sending Rate: {} packets per second, {} bits per second", packet.sent_number, packet.sent_size);
            println!("Receiving Rate: {} packets per second, {} bits per second", packet.received_number, packet.received_size);
            println!("Total Sent: {} packets, {} bits", pack.sent_number, pack.sent_size);
            println!("Total Received: {} packets, {} bits", pack.received_number, pack.received_size);
        } else {
            println!("Process: {} ({})", process.name, process.id);
            println!("Sending Rate: {} packets per second, {} bits per second", 0, 0);
            println!("Receiving Rate: {} packets per second, {} bits per second", 0, 0);
            println!("Total Sent: {} packets, {} bits", pack.sent_number, pack.sent_size);
            println!("Total Received: {} packets, {} bits", pack.received_number, pack.received_size);
        }
    }
    }
    print!("--------------------------------------------------------------------------------------------------------------------\n");
    {
        let mut map = process_packet_map.lock().unwrap();
        map.clear();
    }
}

fn Capture(process_packet_map: &Arc<Mutex<HashMap<Process, Packets>>>, ethernet: EthernetPacket, ip: IpAddr, packet_length: u32){
    let ss_out = Command::new("ss")
            .arg("-p")
            .arg("-n")
            .arg("-t")
            .arg("-u")
            .output()
            .expect("Failed to execute command");
        let ss_output = str::from_utf8(&ss_out.stdout).unwrap();
        let lines = ss_output.lines();
        //use pnet to analyze the captured packet and obtain its source port and address
        if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
            let address = ipv4.get_source();
            let port;
            match ipv4.get_next_level_protocol() {
                pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                        port = tcp.get_source();
                        let search_string = format!("{}:{}", address, port);
                        for line in lines {
                            // Check if the line contains the search string
                            if line.contains(&search_string) {
                                // Create a regular expression to match the PID pattern
                                let re = Regex::new(r"pid=(\d+)").unwrap();

                                // Search for the PID in the line
                                if let Some(captures) = re.captures(&line) {
                                    if let Some(pid) = captures.get(1) {
                                        let pid_num = pid.as_str().parse::<u32>().unwrap(); // Convert the pid string to a number

                                        // Get the process name
                                        let output = Command::new("ps")
                                            .arg("-p")
                                            .arg(pid.as_str())
                                            .arg("-o")
                                            .arg("comm=")
                                            .output()
                                            .expect("Failed to execute command");
                                        let process_name = String::from_utf8(output.stdout).unwrap().trim().to_string();

                                        let mut map = process_packet_map.lock().unwrap();
                                        let pack = map.entry(Process { id: pid_num, name: process_name })
                                            .or_insert(Packets { sent_size: 0, received_size: 0, sent_number: 0, received_number: 0 });
                                        if address == ip {
                                            pack.sent_size += (packet_length * 8) as u32;
                                            pack.sent_number += 1;
                                        } else {
                                            pack.received_size += (packet_length * 8) as u32;
                                            pack.received_number += 1;
                                        }
                                    }
                                }
                            }
                        }

                    /*   port = tcp.get_destination();
                        address = ipv4.get_destination();
                        let outgoing = Command::new("ss")
                            .arg("-p")
                            .arg("-n")
                            .arg("-t")
                            .arg("dst")
                            .arg(format!("{}:{}", address, port))
                            .output()
                            .expect("Failed to execute command");

                        let income = str::from_utf8(&incoming.stdout).unwrap();
                        let outcome = str::from_utf8(&outgoing.stdout).unwrap();
                        println!("Input: {}", income);
                        println!("Output: {}", outcome);
                        println!("{}:{}", address, port);*/
                    }
                },
                pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                    if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                        port = udp.get_source();
                        let search_string = format!("{}:{}", address, port);
                        for line in lines {
                            // Check if the line contains the search string
                            if line.contains(&search_string) {
                                // Create a regular expression to match the PID pattern
                                let re = Regex::new(r"pid=(\d+)").unwrap();
                                // Search for the PID in the line
                                if let Some(captures) = re.captures(&line) {
                                    if let Some(pid) = captures.get(1) {
                                        let pid_num = pid.as_str().parse::<u32>().unwrap(); // Convert the pid string to a number

                                        // Get the process name
                                        let output = Command::new("ps")
                                            .arg("-p")
                                            .arg(pid.as_str())
                                            .arg("-o")
                                            .arg("comm=")
                                            .output()
                                            .expect("Failed to execute command");
                                        let process_name = String::from_utf8(output.stdout).unwrap().trim().to_string();

                                        let mut map = process_packet_map.lock().unwrap();
                                        let pack = map.entry(Process { id: pid_num, name: process_name })
                                            .or_insert(Packets { sent_size: 0, received_size: 0, sent_number: 0, received_number: 0 });
                                        if address == ip {
                                            pack.sent_size += (packet_length * 8) as u32;
                                            pack.sent_number += 1;
                                        } else {
                                            pack.received_size += (packet_length * 8) as u32;
                                            pack.received_number += 1;
                                        }
                                    }
                                }
                            }
                        }
                        /*let incoming = Command::new("ss")
                            .arg("-p")
                            .arg("-n")
                            .arg("-u")
                            .arg("src")
                            .arg(format!("{}:{}", address, port))
                            .output()
                            .expect("Failed to execute command");

                        port = udp.get_destination();
                        address = ipv4.get_destination();
                        let outgoing = Command::new("ss")
                            .arg("-p")
                            .arg("-n")
                            .arg("-u")
                            .arg("dst")
                            .arg(format!("{}:{}", address, port))
                            .output()
                            .expect("Failed to execute command");

                        let income = str::from_utf8(&incoming.stdout).unwrap();
                        let outcome = str::from_utf8(&outgoing.stdout).unwrap();
                        println!("Input: {}", income);
                        println!("Output: {}", outcome);
                        println!("{}:{}", address, port);*/
                    }
                },
                _ => {
                    println!("Lost a packet!");
                }
            }
        }
}

