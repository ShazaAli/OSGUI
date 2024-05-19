
// // Import necessary dependencies
// extern crate pcap;
// extern crate pnet;
// // std imports
// use std::cell::RefCell;
// use std::collections::HashMap;
// use std::fmt;
// use std::net::IpAddr;
// use std::process::Command;
// use std::str;
// use std::sync::{Arc, Mutex};
// use std::thread;
// use std::time::Duration;
// use std::sync::atomic::{AtomicBool, Ordering};

// use iced::widget::container;
// // External crate imports
// use if_addrs::get_if_addrs;
// use iced::{
//     Application, 
//     Settings, 
//     Subscription,
//     Alignment, 
//     Command as IcedCommand, 
//     Element, 
//     Length, 
//     futures::channel::mpsc::Sender, 
//     subscription, 
//     widget::{
//         button,
//         Button, 
//         text::Text, 
//         Row, 
//         Column, 
//         Space, 
//         Container
//     }
// };
// use iced_native::Align;
// use plotters::series;
// use pnet::packet::{
//     Packet, 
//     ethernet::EthernetPacket, 
//     ipv4::Ipv4Packet, 
//     tcp::TcpPacket, 
//     udp::UdpPacket
// };
// use regex::Regex;

// // Define the Process struct
// #[derive(Clone, Hash, Eq, PartialEq)]
// pub struct Process {
//     id: u32,
//     name: String,
// }

// // Define the Packet struct
// #[derive(Clone, Debug)]
// struct Packets {
//     sent_size: u32,
//     received_size: u32,
//     sent_number: u32,
//     received_number: u32,
// }
// impl ToString for Packets {
//     fn to_string(&self) -> String {
//         format!(
//             "Sent Size: {}, Received Size: {}, Sent Number: {}, Received Number: {}",
//             self.sent_size, self.received_size, self.sent_number, self.received_number
//         )
//     }
// }

// impl Packets {
//     pub fn new( sent_size: u32,
//     received_size: u32,
//     sent_number: u32,
//     received_number: u32) -> Self {
//         Self {
//             sent_size,
//             received_size,
//             sent_number,
//             received_number,
//         }
//     }
// }
// enum Page {
//     TablePage,
//     GraphPage,
//     ConfigPage,
// }
// // Usage
// struct App {
//     page: Page,
//     data: HashMap<Process, Packets>,
//     receiver: RefCell<Option<std::sync::mpsc::Receiver<Message>>>,
//     config_button: button::State,
//     graph_button: button::State,
//     table_button1: button::State,
//     table_button2: button::State,
// }

// #[derive(Clone)]
// enum Message {
//     NewData(HashMap<Process, Packets>),
//     NavigateToTablePage,
//     NavigateToGraphPage,
//     NavigateToConfigPage,
//     // other messages...
// }

// impl fmt::Debug for Message {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         match self {
//             Message::NewData(data) => {
//                 // If you can't print `data`, just print a placeholder
//                 f.debug_struct("NewData")
//                  .field("data", &"Non-debuggable data")
//                  .finish()
//             },
//             Message::NavigateToTablePage => Ok(()),
//             Message::NavigateToGraphPage => Ok(()),
//             Message::NavigateToConfigPage => Ok(()),
//         }
//     }
// }



// impl Application for App {
//     type Executor = iced::executor::Default;
//     type Message = Message;
//     type Flags = UiFlags;
//     type Theme= iced::Theme;
//     // fn new(flags: UiFlags) -> (Self, Command<Message>) {
//     //     let app = Ui {
//     //         receiver: RefCell::new(Some(flags.receiver)),
//     //         num: 0,
//     //     };
//     //     (app, Command::none())
//     // }

//     fn new(flags: UiFlags) -> (App, IcedCommand<Self::Message>) {
//         (App {
//             page: Page::TablePage, 
//             data: HashMap::new(),
//             receiver:RefCell::new(Some(flags.receiver)),
//             config_button: button::State::new(),
//             graph_button: button::State::new(),
//             table_button1: button::State::new(),
//             table_button2: button::State::new(),
//         }, IcedCommand::none())
//     }

//     fn title(&self) -> String {
//         String::from("My Window")
//     }

//     fn update(&mut self, message: Self::Message) -> IcedCommand<Self::Message> {
//         match message {
//             Message::NewData(new_data) => {
//                 self.data = new_data;
//                 /*for (process, packets) in new_data {
//                     self.data.entry(process).or_insert(packets);
//                 }*/            }
//             Message::NavigateToTablePage => {
//                 self.page = Page::TablePage;
//             }
//             Message::NavigateToConfigPage => {
//                 self.page = Page::ConfigPage;
//             }
//             Message::NavigateToGraphPage => {
//                 self.page = Page::GraphPage;
//             }
//             // handle other messages...
//         }
//         IcedCommand::none()
//     }
//     fn view(& self) -> Element<Self::Message> {
//         match self.page{
//             Page::TablePage => {
//                 let mut table = Column::new();
//                 let row = Row::new()
//                     .push(Container::new(Text::new(format!("{: >20}","process"))).padding(20)) // Add padding
//                     .push(Container::new(Text::new(format!("{: >20}","sent size"))).padding(20)) // Add padding
//                     .push(Container::new(Text::new(format!("{: >20}","received size"))).padding(20)) // Add padding
//                     .push(Container::new(Text::new(format!("{: >20}","sent number"))).padding(20)) // Add padding
//                     .push(Container::new(Text::new(format!("{: >20}","received number"))).padding(20)); // Add padding
//                 table = table.push(row);
//                 for (process, packets) in &self.data {
//                     let row = Row::new()
//                         .push(Container::new(Text::new(format!("{}",process.name.clone()))).padding(20)) // Add padding
//                         .push(Container::new(Text::new(format!("{: >20}",packets.sent_size))).padding(20)) // Add padding
//                         .push(Container::new(Text::new(format!("{: >20}",packets.received_size))).padding(20)) // Add padding
//                         .push(Container::new(Text::new(format!("{: >20}",packets.sent_number))).padding(20)) // Add padding
//                         .push(Container::new(Text::new(format!("{: >20}",packets.received_number))).padding(20)); // Add padding
//                     table = table.push(iced::widget::Rule::horizontal(10)); // Add a horizontal line
//                     table = table.push(row);
//                 }

//                 /// Create a row for the buttons
//                 let buttons = Row::new()
//                     .push(Button::new("Graph").on_press(Message::NavigateToGraphPage))
//                     .push(Button::new("Configurations").on_press(Message::NavigateToConfigPage))
//                     .align_items(Alignment::Center);

//                 // Add the row to the column and align it to the bottom
//                 table = table.push(Space::with_height(Length::Fill)); // This will push the buttons to the bottom
//                 table = table.push(buttons).align_items(Alignment::Center);
//                 //table = table.align_items(Alignment::End);

//                 table.into()
//             }
//             Page::GraphPage => {
//                 let mut graph_page = Column::new();
//                 //let series = Series::new(self.data,plotters_iced::series::LineSeries::new());
//                 graph_page = graph_page.push(Button::new("Back").on_press(Message::NavigateToTablePage));
//                 // let chart = ChartBuilder::default()
//                 //     .margin(5)
//                 //     .caption("Example Chart", ("Arial", 50).into_font())
//                 //     .x_label_area_size(30)
//                 //     .y_label_area_size(30)
//                 //     .build_cartesian_2d(0f32..10f32, 0f32..10f32)
//                 //     .unwrap()
//                 //     .configure_mesh()
//                 //     .draw()
//                 //     .unwrap()
//                 //     .draw_series(series)
//                 //     .unwrap();
//                 // Add the chart to your page
//                 //graph_page = graph_page.push(chart);
//                 // let button = Button::new(&mut self.table_button1)
//                 //     .on_press(Message::NavigateToTablePage);
//                 // graph_page = graph_page.push(button);
            
//                 graph_page.into()
//             }
//             Page::ConfigPage => {
//                 let mut config_page = Column::new().push(Text::new("Config page"));
//                 config_page = config_page.push(Button::new("Back").on_press(Message::NavigateToTablePage));
//                 // let button = Button::new(&mut self.table_button1)
//                 //     .on_press(Message::NavigateToTablePage);
//                 // config_page = config_page.push(button);
            
//                 config_page.into()
//             }
//         }
        
//     }
//     fn subscription(&self) -> Subscription<Message> {
//         subscription::unfold(
//             "led changes",
//             self.receiver.take(),
//             move |mut receiver| async move {
//                 let process_packets = receiver.as_mut().unwrap().recv().unwrap();
//                 (process_packets, receiver)
//             },
//         )
//     }
// }
// struct UiFlags {
//     receiver:std::sync::mpsc::Receiver<Message>,
// }

// fn main() {
//     let mut runtime = tokio::runtime::Runtime::new().unwrap();
//     let running = Arc::new(AtomicBool::new(true));
//     let rc = Arc::clone(&running);

//     // Move the creation of the runtime and the async block into a separate function
//     fn run_async(running: Arc<AtomicBool>) {
//         let mut runtime = tokio::runtime::Runtime::new().unwrap();

//         runtime.block_on(async {
//             let (sender, receiver) = std::sync::mpsc::channel();

//     let network_task = tokio::spawn(async move{

    
//     // Choose the network interface for capturing. E.g., "eth0"
//     let interface = "enp0s3";
//     let if_addrs = get_if_addrs().unwrap();
//     let interface_addr = if_addrs.iter()
//         .find(|if_addr| if_addr.name == interface && !if_addr.addr.is_loopback())
//         .expect("No such interface or interface does not have an IP address");

//     let ip = interface_addr.addr.ip();

//     // Define the HashMap
//     let process_packet_map: Arc<Mutex<HashMap<Process, Packets>>> = Arc::new(Mutex::new(HashMap::new()));
//     let global_process_packet_map: Arc<Mutex<HashMap<Process, Packets>>> = Arc::new(Mutex::new(HashMap::new()));

//     let ss_output_map: Arc<Mutex<HashMap<String, Process>>> = Arc::new(Mutex::new(HashMap::new()));
//     let ss_map_for_thread = Arc::clone(&ss_output_map);
//     let running_clone = Arc::clone(&running);
//     thread::spawn(move || {
//         while running_clone.load(Ordering::SeqCst) {
//             // Run the ss command
//             SSUpdate(&ss_map_for_thread, ip);

//             // Sleep for a while before the next update
//             thread::sleep(Duration::from_millis(10));
//             println!("SSUpdate");
//         }
//     });

//     // In your main function, clone the Arc before moving it into the thread
//     let map_for_thread = Arc::clone(&process_packet_map);
//     let global_map_for_thread = Arc::clone(&global_process_packet_map);
//     let running_clone2 = Arc::clone(&running);
//     // Spawn a new thread for printing the live outputs
//     thread::spawn(move || {
//         while running_clone2.load(Ordering::SeqCst){
//             Monitor(&map_for_thread, &global_map_for_thread);
//             let new_data = global_map_for_thread.lock().unwrap().clone();
//             match sender.send(Message::NewData(new_data)) {
//                 Ok(_) => {},
//                 Err(e) => {return},
//             };
//             thread::sleep(Duration::from_secs(1));
//             println!("Monitor");
//         }
//     });

//     // Open the capture for the given interface
//     let mut cap = pcap::Capture::from_device(interface).unwrap()
//         .promisc(true)  // Set the capture mode to promiscuous
//         .snaplen(5000)  // Set the maximum bytes to capture per packet
//         .open().unwrap();

//     let running_clone3 = Arc::clone(&running);
//     // Start capturing packets
//     while let Ok(packet) = cap.next() {
//         println!("Packet captured");
//         if !running_clone3.load(Ordering::SeqCst){
//             return;
//         }
//         let packet_data = packet.data.to_vec();
//         let ethernet = EthernetPacket::owned(packet_data).unwrap();
//         let len = packet.data.len() as u32;
//         let IPC = ip.clone();
//         let map_for_thread = Arc::clone(&process_packet_map);
//         let map_for_thread_clone = Arc::clone(&map_for_thread);
//         let ss_map_for_thread = Arc::clone(&ss_output_map);
//         thread::spawn(move || {
//                 Capture(&map_for_thread, ethernet, IPC, len,&ss_map_for_thread);
//         });

//     }

//     });
//     App::run(Settings::with_flags(UiFlags { receiver }));
//     });

//         // The runtime is dropped here, which is outside of the async block
//     }
//     run_async(running);
//     println!("App::run");
//     rc.store(false, Ordering::SeqCst);
// }



// fn Monitor(process_packet_map: &Arc<Mutex<HashMap<Process, Packets>>>, global_process_packet_map: &Arc<Mutex<HashMap<Process, Packets>>>) {
//     // Lock the Mutex before accessing the HashMap
//     {
//     let map = process_packet_map.lock().unwrap();
//     let mut global_map = global_process_packet_map.lock().unwrap();

//     // Print the process packet map
//     for (process, packet) in &*map {
//         let pack = global_map.entry(process.clone())
//             .or_insert(Packets { sent_size: 0, received_size: 0, sent_number: 0, received_number: 0 });
//         pack.sent_size += packet.sent_size;
//         pack.received_size += packet.received_size;
//         pack.sent_number += packet.sent_number;
//         pack.received_number += packet.received_number;                                
//     }
//     }
//     {
//     let map = process_packet_map.lock().unwrap();
//     let global_map = global_process_packet_map.lock().unwrap();

//     for (process, pack) in &*global_map {
//         if let Some(packet) = map.get(&process) {
//             println!("Process: {} ({})", process.name, process.id);
//             println!("Sending Rate: {} packets per second, {} bits per second", packet.sent_number, packet.sent_size);
//             println!("Receiving Rate: {} packets per second, {} bits per second", packet.received_number, packet.received_size);
//             println!("Total Sent: {} packets, {} bits", pack.sent_number, pack.sent_size);
//             println!("Total Received: {} packets, {} bits", pack.received_number, pack.received_size);
//         } else {
//             println!("Process: {} ({})", process.name, process.id);
//             println!("Sending Rate: {} packets per second, {} bits per second", 0, 0);
//             println!("Receiving Rate: {} packets per second, {} bits per second", 0, 0);
//             println!("Total Sent: {} packets, {} bits", pack.sent_number, pack.sent_size);
//             println!("Total Received: {} packets, {} bits", pack.received_number, pack.received_size);
//         }
//     }
//     }
//     print!("--------------------------------------------------------------------------------------------------------------------\n");
//     {
//         let mut map = process_packet_map.lock().unwrap();
//         map.clear();
//     }
// }

// fn Capture(process_packet_map: &Arc<Mutex<HashMap<Process, Packets>>>, ethernet: EthernetPacket, ip: IpAddr, packet_length: u32, ports: &Arc<Mutex<HashMap<String, Process>>>){
//     //use pnet to analyze the captured packet and obtain its source port and address
//     if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
//         let address = ipv4.get_source();
//         let port;
//         match ipv4.get_next_level_protocol() {
//             pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
//                 if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
//                     if address == ip {
//                         port = tcp.get_source();
//                     } else {
//                         port = tcp.get_destination();
//                     }

//                     // Get the process name and info from the ports map
//                     let ports_map = ports.lock().unwrap();
//                     match ports_map.get(&port.to_string()) {
//                         Some(process) => {
//                             let mut map = process_packet_map.lock().unwrap();
//                             let pack = map.entry(process.clone())
//                                 .or_insert(Packets { sent_size: 0, received_size: 0, sent_number: 0, received_number: 0 });
//                             if address == ip {
//                                 pack.sent_size += (packet_length * 8) as u32;
//                                 pack.sent_number += 1;
//                             } else {
//                                 pack.received_size += (packet_length * 8) as u32;
//                                 pack.received_number += 1;
//                             }
//                         },
//                         None => println!("Error: No process found for port {}", port),
//                     }
//                 }
//             },
//             pnet::packet::ip::IpNextHeaderProtocols::Udp => {
//                 if let Some(udp) = UdpPacket::new(ipv4.payload()) {
//                     if address == ip{
//                         port = udp.get_source();
//                     } else {
//                         port = udp.get_destination();
//                     }

//                     // Get the process name and info from the ports map
//                     let ports_map = ports.lock().unwrap();
//                     match ports_map.get(&port.to_string()) {
//                         Some(process) => {
//                             let mut map = process_packet_map.lock().unwrap();
//                             let pack = map.entry(process.clone())
//                                 .or_insert(Packets { sent_size: 0, received_size: 0, sent_number: 0, received_number: 0 });
//                             if address == ip {
//                                 pack.sent_size += (packet_length * 8) as u32;
//                                 pack.sent_number += 1;
//                             } else {
//                                 pack.received_size += (packet_length * 8) as u32;
//                                 pack.received_number += 1;
//                             }
//                         },
//                         None => println!("Error: No process found for port {}", port),
//                     }
//                 }
//             },
//             _ => {
//                 println!("A non-TCP/UDP packet was captured");
//             }
//         }
//     }
// }


// fn SSUpdate(ss_map_for_thread: &Arc<Mutex<HashMap<String, Process>>>, ip: IpAddr){
//     let ss_out = Command::new("ss")
//         .arg("-p")
//         .arg("-n")
//         .arg("-t")
//         .arg("-u")
//         .arg("-l")
//         .output()
//         .expect("Failed to execute command");
//     let ss_output = str::from_utf8(&ss_out.stdout).unwrap();
//     //print!("{}", ss_output);

//     // Call ps command and create a map from pid to process name
//     let ps_out = Command::new("ps")
//         .arg("-e")
//         .arg("-o")
//         .arg("pid,comm")
//         .output()
//         .expect("Failed to execute command");
//     let ps_output = str::from_utf8(&ps_out.stdout).unwrap();
//     let mut pid_to_name = HashMap::new();
//     for line in ps_output.lines().skip(1) { // Skip the header line
//         let parts: Vec<&str> = line.split_whitespace().collect();
//         if parts.len() >= 2 {
//             pid_to_name.insert(parts[0].to_string(), parts[1].to_string());
//         }
//     }

//     // Parse the output and update the shared map
//     let mut map = ss_map_for_thread.lock().unwrap();
//     for line in ss_output.lines() {
//         // Create the regular expressions
//         let re_port = Regex::new(&format!(r"({}|0.0.0.0):(\d+)", ip)).unwrap();
//         let re_pid = Regex::new(r"pid=(\d+)").unwrap();

//         // Use the regular expressions to extract the port number and the PID
//         let port = re_port.captures(line).and_then(|cap| cap.get(2)).map(|m| m.as_str().to_string()).unwrap_or(String::new());
//         let pid = re_pid.captures(line).and_then(|cap| cap.get(1)).map(|m| m.as_str());

//         // Get the process name from the pid_to_name map
//         if let Some(pid) = pid {
//             let process_name = pid_to_name.get(pid);

//             // Insert the pid and process name into the map
//             if let Some(process_name) = process_name {
//                 let pid_u32 = pid.parse::<u32>().unwrap_or(0);
//                 map.insert(port, Process{id : pid_u32, name : process_name.to_string()});
//             }
//         }
//     }

// }

