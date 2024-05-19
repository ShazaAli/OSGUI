// plotters-iced
//
// Iced backend for Plotters
// Copyright: 2022, Joylei <leingliu@gmail.com>
// License: MIT

// Import necessary dependencies
extern crate pcap;
extern crate pnet;
extern crate iced;
extern crate plotters;
extern crate sysinfo;

use chrono::{DateTime, TimeZone, Utc};
use iced::{
    alignment::{Horizontal, Vertical},
    executor, font,
    widget::{
        canvas::{Cache, Frame, Geometry},
        Column, Container, Row, Scrollable, Space, Text, button, Button, 
    },
    Alignment, Application, Command, Element, Font, Length, Settings, Size, Subscription, Theme, subscription,
    futures::channel::mpsc::Sender, 

};
use iced::widget::TextInput;
lazy_static::lazy_static! {
    static ref MAX_TOTAL_SENT: tokio::sync::RwLock<u32> = tokio::sync::RwLock::new(0);
    static ref MAX_TOTAL_RECEIVED: tokio::sync::RwLock<u32> = tokio::sync::RwLock::new(0);
    static ref LOGGING_FREQUENCY: tokio::sync::RwLock<u32> = tokio::sync::RwLock::new(0);
}


use plotters::prelude::ChartBuilder;
use plotters_backend::DrawingBackend;
use plotters_iced::{Chart, ChartWidget, Renderer};
// std imports
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::process::Command as PrcCommand;
use std::str;
use std::sync::{Arc, Mutex};
use std::thread;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};
use sysinfo::{CpuRefreshKind, RefreshKind, System};

use if_addrs::get_if_addrs;
use iced_native::Align;
use pnet::packet::{
    Packet, 
    ethernet::EthernetPacket, 
    ipv4::Ipv4Packet, 
    tcp::TcpPacket, 
    udp::UdpPacket
};
use regex::Regex;


const PLOT_SECONDS: usize = 60; //1 min
const TITLE_FONT_SIZE: u16 = 22;
const SAMPLE_EVERY: Duration = Duration::from_millis(1000);

const FONT_BOLD: Font = Font {
    family: font::Family::Name("Noto Sans"),
    weight: font::Weight::Bold,
    ..Font::DEFAULT
};

// Define the Process struct
#[derive(Clone, Hash, Eq, PartialEq)]
pub struct Process {
    id: u32,
    name: String,
}

// Define the Packet struct
#[derive(Clone, Debug)]
struct Packets {
    sent_size: u32,
    received_size: u32,
    sent_number: u32,
    received_number: u32,
    bandwidth: u32,
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
    received_number: u32,
    bandwidth: u32) -> Self {
        Self {
            sent_size,
            received_size,
            sent_number,
            received_number,
            bandwidth,
        }
    }
}

enum Page {
    TablePage,
    GraphPage,
    ConfigPage,
}

#[derive(Clone)]
enum Message {
    /// message that cause charts' data lazily updated
    Tick,
    FontLoaded(Result<(), font::Error>),
    NewData(HashMap<Process, Packets>),
    NavigateToTablePage,
    NavigateToGraphPage,
    NavigateToConfigPage,
    MaxTotalSentChanged(String),
    MaxTotalReceivedChanged(String),
    LoggingFrequencyChanged(String),
    EnterPressed,
}

struct State {
    chart: SystemChart,
    page: Page,
    data: HashMap<Process, Packets>,
    receiver: RefCell<Option<std::sync::mpsc::Receiver<Message>>>,
    max_total_sent_state: TextInput::State,
    max_total_sent: String,
    max_total_received_state: TextInput::State,
    max_total_received: String,
    logging_frequency_state: TextInput::State,
    logging_frequency: String,
    enter_button_state: button::State,
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
            _ => Ok(()),
        }
    }
}


impl Application for State {
    type Message = self::Message;
    type Executor = executor::Default;
    type Flags = UiFlags;
    type Theme = Theme;

    fn new(_flags: Self::Flags) -> (Self, Command<Self::Message>) {
        (
            Self {
                chart: Default::default(),
                page: Page::TablePage, 
                data: HashMap::new(),
                receiver:RefCell::new(Some(_flags.receiver)),
            },
            Command::batch([
                font::load(include_bytes!("./fonts/notosans-regular.ttf").as_slice())
                    .map(Message::FontLoaded),
                font::load(include_bytes!("./fonts/notosans-bold.ttf").as_slice())
                    .map(Message::FontLoaded),
            ]),
        )
    }

    fn title(&self) -> String {
        "Process Internet Monitor".to_owned()
    }

    fn update(&mut self, message: Self::Message) -> Command<Self::Message> {
        match message {
            Message::Tick => {
                self.chart.update(self.data.clone());
            }
            Message::NewData(new_data) => {
                self.data = new_data;
                /*for (process, packets) in new_data {
                    self.data.entry(process).or_insert(packets);
                }*/            }
            Message::NavigateToTablePage => {
                self.page = Page::TablePage;
            }
            Message::NavigateToConfigPage => {
                self.page = Page::ConfigPage;
            }
            Message::NavigateToGraphPage => {
                self.page = Page::GraphPage;
            }
            Message::MaxTotalSentChanged(value) => self.max_total_sent = value,
            Message::MaxTotalReceivedChanged(value) => self.max_total_received = value,
            Message::LoggingFrequencyChanged(value) => self.logging_frequency = value,
            Message::EnterPressed => {
                // Update the global variables
                let max_total_sent = self.max_total_sent.parse().unwrap_or(0);
                let max_total_received = self.max_total_received.parse().unwrap_or(0);
                let logging_frequency = self.logging_frequency.parse().unwrap_or(0);

                let mut max_total_sent_lock = MAX_TOTAL_SENT.write().await;
                                *max_total_sent_lock = max_total_sent;

                let mut max_total_received_lock = MAX_TOTAL_RECEIVED.write().await;
                *max_total_received_lock = max_total_received;

                let mut logging_frequency_lock = LOGGING_FREQUENCY.write().await;
                *logging_frequency_lock = logging_frequency;
         
        }
        Command::none()
    }
    }
    fn view(& self) -> Element<Self::Message> {
        match self.page{
            Page::TablePage => {
                let mut table = Column::new();
                let row = Row::new()
                    .push(Container::new(Text::new(format!("{: >20}","process"))).padding(20)) // Add padding
                    .push(Container::new(Text::new(format!("{: >20}","sent size"))).padding(20)) // Add padding
                    .push(Container::new(Text::new(format!("{: >20}","received size"))).padding(20)) // Add padding
                    .push(Container::new(Text::new(format!("{: >20}","sent number"))).padding(20)) // Add padding
                    .push(Container::new(Text::new(format!("{: >20}","received number"))).padding(20)) // Add padding
                    .push(Container::new(Text::new(format!("{: >20}","bandwidth"))).padding(20)); // Add padding
                table = table.push(row);
                for (process, packets) in &self.data {
                    let row = Row::new()
                        .push(Container::new(Text::new(format!("{}",process.name.clone()))).padding(20)) // Add padding
                        .push(Container::new(Text::new(format!("{: >20}",packets.sent_size))).padding(20)) // Add padding
                        .push(Container::new(Text::new(format!("{: >20}",packets.received_size))).padding(20)) // Add padding
                        .push(Container::new(Text::new(format!("{: >20}",packets.sent_number))).padding(20)) // Add padding
                        .push(Container::new(Text::new(format!("{: >20}",packets.received_number))).padding(20)) // Add padding
                        .push(Container::new(Text::new(format!("{: >30}",packets.bandwidth))).padding(20)); // Add padding
                    table = table.push(iced::widget::Rule::horizontal(10)); // Add a horizontal line
                    table = table.push(row);
                }

                /// Create a row for the buttons
                let buttons = Row::new()
                    .push(Button::new("Graph").on_press(Message::NavigateToGraphPage))
                    .push(Button::new("Configurations").on_press(Message::NavigateToConfigPage))
                    .align_items(Alignment::Center);

                // Add the row to the column and align it to the bottom
                table = table.push(Space::with_height(Length::Fill)); // This will push the buttons to the bottom
                table = table.push(buttons).align_items(Alignment::Center);
                //table = table.align_items(Alignment::End);

                table.into()
            }
            Page::GraphPage => {
                let mut content = Column::new()
                    .spacing(20)
                    .align_items(Alignment::Start)
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .push(
                        Text::new("Iced test chart")
                            .size(TITLE_FONT_SIZE)
                            .font(FONT_BOLD),
                    )
                    .push(self.chart.view());

                content = content.push(Button::new("Back").on_press(Message::NavigateToTablePage));

                Container::new(content)
                    //.style(style::Container)
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .padding(5)
                    .center_x()
                    .center_y()
                    .into()
            }
            Page::ConfigPage => {
                Column::new()
                .push(
                    TextInput::new(
                        &mut self.max_total_sent_state,
                        "Max total sent data",
                        &self.max_total_sent,
                        Message::MaxTotalSentChanged,
                    ),
                )
                .push(
                    TextInput::new(
                        &mut self.max_total_received_state,
                        "Max total received data",
                        &self.max_total_received,
                        Message::MaxTotalReceivedChanged,
                    ),
                )
                .push(
                    TextInput::new(
                        &mut self.logging_frequency_state,
                        "Logging frequency time in seconds",
                        &self.logging_frequency,
                        Message::LoggingFrequencyChanged,
                    ),
                )
                .push(
                    Button::new(&mut self.enter_button_state, Text::new("Enter"))
                        .on_press(Message::EnterPressed),
                )
                .into()
            }
        }
                
    }

    fn subscription(&self) -> Subscription<Message> {
        const FPS: u64 = 50;
        let tick_subscription = iced::time::every(Duration::from_millis(1000 / FPS)).map(|_| Message::Tick);
    
        let led_changes_subscription = subscription::unfold(
            "led changes",
            self.receiver.take(),
            move |mut receiver| async move {
                let process_packets = receiver.as_mut().unwrap().recv().unwrap();
                (process_packets, receiver)
            },
        );
    
        Subscription::batch(vec![tick_subscription, led_changes_subscription])
    }
}
struct UiFlags {
    receiver:std::sync::mpsc::Receiver<Message>,
}

struct SystemChart {
    sys: System,
    last_sample_time: Instant,
    items_per_row: usize,
    processors: Vec<CpuUsageChart>,
    chart_height: f32,
}

impl Default for SystemChart {
    fn default() -> Self {
        Self {
            sys: System::new_with_specifics(
                RefreshKind::new().with_cpu(CpuRefreshKind::new().with_cpu_usage()),
            ),
            last_sample_time: Instant::now(),
            items_per_row: 3,
            processors: Default::default(),
            chart_height: 300.0,
        }
    }
}


impl SystemChart {
    #[inline]
    fn is_initialized(&self) -> bool {
        !self.processors.is_empty()
    }

    #[inline]
    fn should_update(&self) -> bool {
        !self.is_initialized() || self.last_sample_time.elapsed() > SAMPLE_EVERY
    }

    fn update(&mut self, data1: HashMap<Process, Packets>) {
        if !self.should_update() {
            return;
        }
    
        self.sys.refresh_cpu();
        self.last_sample_time = Instant::now();
        let now = Utc::now();
    
        //check if initialized
        if !self.is_initialized() {
            let mut processors: Vec<_> = data1
                .into_iter()
                .map(|(process, packets)| CpuUsageChart::new(vec![(now, packets.bandwidth as i32)].into_iter(), process.name))
                .collect();
            self.processors.append(&mut processors);
        } else {
            // Find new processes
            let new_processes: HashMap<_, _> = data1
                .clone()
                .into_iter()
                .filter(|(process, _)| !self.processors.iter().any(|p| p.name == process.name))
                .collect();
    
            // Append new processes to processors
            let mut new_processors: Vec<_> = new_processes
                .into_iter()
                .map(|(process, packets)| CpuUsageChart::new(vec![(now, packets.bandwidth as i32)].into_iter(), process.name))
                .collect();
            self.processors.append(&mut new_processors);
    
            // Update existing processors
            for ((process, packets), p) in data1.into_iter().zip(self.processors.iter_mut()) {
                if process.name == p.name {
                    p.push_data(now, packets.bandwidth as i32);
                }
            }
        }
    }

    fn view(&self) -> Element<Message> {
        if !self.is_initialized() {
            Text::new("Loading...")
                .horizontal_alignment(Horizontal::Center)
                .vertical_alignment(Vertical::Center)
                .into()
        } else {
            let mut col = Column::new()
                .width(Length::Fill)
                .height(Length::Shrink)
                .align_items(Alignment::Center);

            let chart_height = self.chart_height;
            let mut idx = 0;
            for chunk in self.processors.chunks(self.items_per_row) {
                let mut row = Row::new()
                    .spacing(15)
                    .padding(20)
                    .width(Length::Fill)
                    .height(Length::Shrink)
                    .align_items(Alignment::Center);
                for item in chunk {
                    row = row.push(item.view(idx, chart_height));
                    idx += 1;
                }
                while idx % self.items_per_row != 0 {
                    row = row.push(Space::new(Length::Fill, Length::Fixed(50.0)));
                    idx += 1;
                }
                col = col.push(row);
            }

            Scrollable::new(col).height(Length::Shrink).into()
        }
    }
}

struct CpuUsageChart {
    cache: Cache,
    data_points: VecDeque<(DateTime<Utc>, i32)>,
    limit: Duration,
    name: String,
}

impl CpuUsageChart {
    fn new(data: impl Iterator<Item = (DateTime<Utc>, i32)>, n: String) -> Self {
        let data_points: VecDeque<_> = data.collect();
        Self {
            cache: Cache::new(),
            data_points,
            limit: Duration::from_secs(PLOT_SECONDS as u64),
            name: n,
        }
    }

    fn push_data(&mut self, time: DateTime<Utc>, value: i32) {
        let cur_ms = time.timestamp_millis();
        self.data_points.push_front((time, value));
        loop {
            if let Some((time, _)) = self.data_points.back() {
                let diff = Duration::from_millis((cur_ms - time.timestamp_millis()) as u64);
                if diff > self.limit {
                    self.data_points.pop_back();
                    continue;
                }
            }
            break;
        }
        self.cache.clear();
    }

    fn view(&self, idx: usize, chart_height: f32) -> Element<Message> {
        Column::new()
            .width(Length::Fill)
            .height(Length::Shrink)
            .spacing(5)
            .align_items(Alignment::Center)
            .push(Text::new(format!("{}", self.name)))
            .push(ChartWidget::new(self).height(Length::Fixed(chart_height)))
            .into()
    }
}

impl Chart<Message> for CpuUsageChart {
    type State = ();
    // fn update(
    //     &mut self,
    //     event: Event,
    //     bounds: Rectangle,
    //     cursor: Cursor,
    // ) -> (event::Status, Option<Message>) {
    //     self.cache.clear();
    //     (event::Status::Ignored, None)
    // }

    #[inline]
    fn draw<R: Renderer, F: Fn(&mut Frame)>(
        &self,
        renderer: &R,
        bounds: Size,
        draw_fn: F,
    ) -> Geometry {
        renderer.draw_cache(&self.cache, bounds, draw_fn)
    }

    fn build_chart<DB: DrawingBackend>(&self, _state: &Self::State, mut chart: ChartBuilder<DB>) {
        use plotters::prelude::*;

        const PLOT_LINE_COLOR: RGBColor = RGBColor(0, 175, 255);

        // Acquire time range
        let newest_time = self
            .data_points
            .front()
            .unwrap_or(&(
                Utc.from_utc_datetime(&chrono::NaiveDateTime::from_timestamp_opt(0, 0).unwrap()),
                0,
            ))
            .0;
        let oldest_time = newest_time - chrono::Duration::seconds(PLOT_SECONDS as i64);
        // Find the maximum value in data_points
        let mut max_value = self.data_points.iter().map(|(_, value)| value).max().unwrap_or(&0);
        if *max_value == 0 {
            max_value = &100;
        }
        let mut chart = chart
            .x_label_area_size(0)
            .y_label_area_size(28)
            .margin(50)
            .build_cartesian_2d(oldest_time..newest_time, 0..*max_value)
            .expect("failed to build chart");

        chart
            .configure_mesh()
            .bold_line_style(plotters::style::colors::BLUE.mix(0.1))
            .light_line_style(plotters::style::colors::BLUE.mix(0.05))
            .axis_style(ShapeStyle::from(plotters::style::colors::BLUE.mix(0.45)).stroke_width(1))
            .y_labels(10)
            .y_label_style(
                ("sans-serif", 15)
                    .into_font()
                    .color(&plotters::style::colors::BLUE.mix(0.65))
                    .transform(FontTransform::Rotate90),
            )
            .y_label_formatter(&|y| format!("{}", y))
            .draw()
            .expect("failed to draw chart mesh");

        chart
            .draw_series(
                AreaSeries::new(
                    self.data_points.iter().map(|x| (x.0, x.1)),
                    0,
                    PLOT_LINE_COLOR.mix(0.175),
                )
                .border_style(ShapeStyle::from(PLOT_LINE_COLOR).stroke_width(2)),
            )
            .expect("failed to draw chart data");
    }
}








fn main() {
    let mut runtime = tokio::runtime::Runtime::new().unwrap();
    let running = Arc::new(AtomicBool::new(true));
    let rc = Arc::clone(&running);

    // Move the creation of the runtime and the async block into a separate function
    fn run_async(running: Arc<AtomicBool>) {
        let mut runtime = tokio::runtime::Runtime::new().unwrap();

        runtime.block_on(async {
            let (sender, receiver) = std::sync::mpsc::channel();

    let network_task = tokio::spawn(async move{

    
    // Choose the network interface for capturing. E.g., "eth0"
    let interface = "enp0s3";
    let if_addrs = get_if_addrs().unwrap();
    let interface_addr = if_addrs.iter()
        .find(|if_addr| if_addr.name == interface && !if_addr.addr.is_loopback())
        .expect("No such interface or interface does not have an IP address");

    let ip = interface_addr.addr.ip();

    // Define the HashMap
    let process_packet_map: Arc<Mutex<HashMap<Process, Packets>>> = Arc::new(Mutex::new(HashMap::new()));
    let global_process_packet_map: Arc<Mutex<HashMap<Process, Packets>>> = Arc::new(Mutex::new(HashMap::new()));

    let ss_output_map: Arc<Mutex<HashMap<String, Process>>> = Arc::new(Mutex::new(HashMap::new()));
    let ss_map_for_thread = Arc::clone(&ss_output_map);
    let running_clone = Arc::clone(&running);
    thread::spawn(move || {
        while running_clone.load(Ordering::SeqCst) {
            // Run the ss command
            SSUpdate(&ss_map_for_thread, ip);

            // Sleep for a while before the next update
            thread::sleep(Duration::from_millis(10));
            println!("SSUpdate");
        }
    });

    // In your main function, clone the Arc before moving it into the thread
    let map_for_thread = Arc::clone(&process_packet_map);
    let global_map_for_thread = Arc::clone(&global_process_packet_map);
    let running_clone2 = Arc::clone(&running);
    // Spawn a new thread for printing the live outputs
    thread::spawn(move || {
        while running_clone2.load(Ordering::SeqCst){
            Monitor(&map_for_thread, &global_map_for_thread);
            let new_data = global_map_for_thread.lock().unwrap().clone();
            match sender.send(Message::NewData(new_data)) {
                Ok(_) => {},
                Err(e) => {return},
            };
            thread::sleep(Duration::from_secs(1));
            println!("Monitor");
        }
    });

    // Open the capture for the given interface
    let mut cap = pcap::Capture::from_device(interface).unwrap()
        .promisc(true)  // Set the capture mode to promiscuous
        .snaplen(5000)  // Set the maximum bytes to capture per packet
        .open().unwrap();

    let running_clone3 = Arc::clone(&running);
    // Start capturing packets
    while let Ok(packet) = cap.next() {
        println!("Packet captured");
        if !running_clone3.load(Ordering::SeqCst){
            return;
        }
        let packet_data = packet.data.to_vec();
        let ethernet = EthernetPacket::owned(packet_data).unwrap();
        let len = packet.data.len() as u32;
        let IPC = ip.clone();
        let map_for_thread = Arc::clone(&process_packet_map);
        let map_for_thread_clone = Arc::clone(&map_for_thread);
        let ss_map_for_thread = Arc::clone(&ss_output_map);
        thread::spawn(move || {
                Capture(&map_for_thread, ethernet, IPC, len,&ss_map_for_thread);
        });

    }

    });
        State::run(Settings {
            antialiasing: true,
            default_font: Font::with_name("Noto Sans"),
            ..Settings::with_flags(UiFlags { receiver })
        })
        .unwrap();
    });

        // The runtime is dropped here, which is outside of the async block
    }
    run_async(running);
    println!("App::run");
    rc.store(false, Ordering::SeqCst);
}



fn Monitor(process_packet_map: &Arc<Mutex<HashMap<Process, Packets>>>, global_process_packet_map: &Arc<Mutex<HashMap<Process, Packets>>>) {
    // Lock the Mutex before accessing the HashMap
    {
    let map = process_packet_map.lock().unwrap();
    let mut global_map = global_process_packet_map.lock().unwrap();

    // Print the process packet map
    for (process, packet) in &*map {
        let pack = global_map.entry(process.clone())
            .or_insert(Packets { sent_size: 0, received_size: 0, sent_number: 0, received_number: 0, bandwidth: 0});
        pack.sent_size += packet.sent_size;
        pack.received_size += packet.received_size;
        pack.sent_number += packet.sent_number;
        pack.received_number += packet.received_number; 
        pack.bandwidth = packet.sent_size + packet.received_size;                            
    }
    }
    {
    let map = process_packet_map.lock().unwrap();
    {
    let mut global_map = global_process_packet_map.lock().unwrap();

    for (process, pack) in &mut *global_map {
        if let Some(packet) = map.get(&process) {
            println!("Process: {} ({})", process.name, process.id);
            println!("Sending Rate: {} packets per second, {} bits per second", packet.sent_number, packet.sent_size);
            println!("Receiving Rate: {} packets per second, {} bits per second", packet.received_number, packet.received_size);
            println!("Total Sent: {} packets, {} bits", pack.sent_number, pack.sent_size);
            println!("Total Received: {} packets, {} bits", pack.received_number, pack.received_size);
            println!("Bandwidth: {} bits per second", pack.bandwidth);
        } else {
            println!("Process: {} ({})", process.name, process.id);
            println!("Sending Rate: {} packets per second, {} bits per second", 0, 0);
            println!("Receiving Rate: {} packets per second, {} bits per second", 0, 0);
            println!("Total Sent: {} packets, {} bits", pack.sent_number, pack.sent_size);
            println!("Total Received: {} packets, {} bits", pack.received_number, pack.received_size);
            pack.bandwidth = 0; 
            println!("Bandwidth: {} bits per second", pack.bandwidth);
        }
    }
    }
    }
    print!("--------------------------------------------------------------------------------------------------------------------\n");
    {
        let mut map = process_packet_map.lock().unwrap();
        map.clear();
    }
}

fn Capture(process_packet_map: &Arc<Mutex<HashMap<Process, Packets>>>, ethernet: EthernetPacket, ip: IpAddr, packet_length: u32, ports: &Arc<Mutex<HashMap<String, Process>>>){
    //use pnet to analyze the captured packet and obtain its source port and address
    if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
        let address = ipv4.get_source();
        let port;
        match ipv4.get_next_level_protocol() {
            pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                    if address == ip {
                        port = tcp.get_source();
                    } else {
                        port = tcp.get_destination();
                    }

                    for i in 0..10 {
                        {
                    // Get the process name and info from the ports map
                    let ports_map = ports.lock().unwrap();
                    match ports_map.get(&port.to_string()) {
                        Some(process) => {
                            let mut map = process_packet_map.lock().unwrap();
                            let pack = map.entry(process.clone())
                                .or_insert(Packets { sent_size: 0, received_size: 0, sent_number: 0, received_number: 0 , bandwidth: 0});
                            if address == ip {
                                pack.sent_size += (packet_length * 8) as u32;
                                pack.sent_number += 1;
                            } else {
                                pack.received_size += (packet_length * 8) as u32;
                                pack.received_number += 1;
                            }
                            break;
                        },
                        None => {if i == 9 {println!("Error: No process found for port {}", port)}}
                    }
                        }
                    thread::sleep(Duration::from_millis(100));
                    }
                }
            },
            pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                    if address == ip{
                        port = udp.get_source();
                    } else {
                        port = udp.get_destination();
                    }

                    for i in 0..10 {
                        // Get the process name and info from the ports map
                        {
                        let ports_map = ports.lock().unwrap();
                        match ports_map.get(&port.to_string()) {
                            Some(process) => {
                                let mut map = process_packet_map.lock().unwrap();
                                let pack = map.entry(process.clone())
                                    .or_insert(Packets { sent_size: 0, received_size: 0, sent_number: 0, received_number: 0, bandwidth: 0});
                                if address == ip {
                                    pack.sent_size += (packet_length * 8) as u32;
                                    pack.sent_number += 1;
                                } else {
                                    pack.received_size += (packet_length * 8) as u32;
                                    pack.received_number += 1;
                                }
                                break;
                            },
                            None => {if i == 9 {println!("Error: No process found for port {}", port)}}
                        }
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            },
            _ => {
                println!("A non-TCP/UDP packet was captured");
            }
        }
    }
}


fn SSUpdate(ss_map_for_thread: &Arc<Mutex<HashMap<String, Process>>>, ip: IpAddr){
    let ss_out = PrcCommand::new("ss")
        .arg("-p")
        .arg("-n")
        .arg("-t")
        .arg("-u")
        .arg("-l")
        .output()
        .expect("Failed to execute command");
    let ss_output = str::from_utf8(&ss_out.stdout).unwrap();
    //print!("{}", ss_output);

    // Call ps command and create a map from pid to process name
    let ps_out = PrcCommand::new("ps")
        .arg("-e")
        .arg("-o")
        .arg("pid,comm")
        .output()
        .expect("Failed to execute command");
    let ps_output = str::from_utf8(&ps_out.stdout).unwrap();
    let mut pid_to_name = HashMap::new();
    for line in ps_output.lines().skip(1) { // Skip the header line
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            pid_to_name.insert(parts[0].to_string(), parts[1].to_string());
        }
    }

    // Parse the output and update the shared map
    let mut map = ss_map_for_thread.lock().unwrap();
    for line in ss_output.lines() {
        // Create the regular expressions
        let re_port = Regex::new(&format!(r"({}|0.0.0.0):(\d+)", ip)).unwrap();
        let re_pid = Regex::new(r"pid=(\d+)").unwrap();

        // Use the regular expressions to extract the port number and the PID
        let port = re_port.captures(line).and_then(|cap| cap.get(2)).map(|m| m.as_str().to_string()).unwrap_or(String::new());
        let pid = re_pid.captures(line).and_then(|cap| cap.get(1)).map(|m| m.as_str());

        // Get the process name from the pid_to_name map
        if let Some(pid) = pid {
            let process_name = pid_to_name.get(pid);

            // Insert the pid and process name into the map
            if let Some(process_name) = process_name {
                let pid_u32 = pid.parse::<u32>().unwrap_or(0);
                map.insert(port, Process{id : pid_u32, name : process_name.to_string()});
            }
        }
    }

}

