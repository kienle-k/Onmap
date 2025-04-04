use std::io;
use crate::models::{MainMenuItem, HostDiscoveryOption, PortScanOption, AppState, PortOptions};
use crossterm::event::{self, Event, KeyCode};
use ratatui::{
    backend::Backend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame, Terminal,
};

pub struct App {
    state: AppState,
    main_selected: Option<MainMenuItem>,
    host_discovery_selected: Option<HostDiscoveryOption>,
    port_scan_selected: Option<PortScanOption>,
    ip_input: String,
    port_needed: bool,
    port_mode: Option<PortOptions>,
    port_input: String,
    cursor_position: usize,
}

impl App {
    pub fn new() -> App {
        App { 
            state: AppState::MainMenu,
            main_selected: None,
            host_discovery_selected: None,
            port_scan_selected: None,
            ip_input: String::new(),
            port_needed: false,
            port_mode: None,
            port_input: String::new(),
            cursor_position: 0,
        }
    }

    fn select(&mut self, item: MainMenuItem) {
        self.main_selected = Some(item);
    }

    fn select_host_discovery(&mut self, item: HostDiscoveryOption) {
        self.host_discovery_selected = Some(item);
    }
    
    fn select_port_scan(&mut self, item: PortScanOption) {
        self.port_scan_selected = Some(item);
    }
    fn input_ip(&mut self, c: char) {
        self.ip_input.insert(self.cursor_position, c);
        self.cursor_position += 1;
    }

    fn input_port(&mut self, c: char) {
        self.port_input.insert(self.cursor_position, c);
        self.cursor_position += 1;
    }

    fn delete_char_ip_input(&mut self) {
        if self.cursor_position > 0 {
            self.cursor_position -= 1;
            self.ip_input.remove(self.cursor_position);
        }
    }

    fn delete_char_port_range_input(&mut self) {
        if self.cursor_position > 0 {
            self.cursor_position -= 1;
            self.port_input.remove(self.cursor_position);
        }
    }

    fn move_cursor_left(&mut self) {
        if self.cursor_position > 0 {
            self.cursor_position -= 1;
        }
    }

    fn move_cursor_right(&mut self) {
        if self.cursor_position < self.ip_input.len() {
            self.cursor_position += 1;
        }
    }
}

pub fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> io::Result<(Option<MainMenuItem>,
                Option<HostDiscoveryOption>,
                Option<PortScanOption>,
                String,
                bool,
                Option<PortOptions>,
                String)> {
    loop {
        terminal.draw(|f| ui(f, app))?;

        if let Event::Key(key) = event::read()? {
            match app.state {
                AppState::MainMenu => {
                    match key.code {
                        KeyCode::Char('q') => return Ok((None, None, None, "".to_string(), false, None, "".to_string())),
                        KeyCode::Char('1') => {
                            app.select(MainMenuItem::SubMenuHostDiscovery);
                            app.state = AppState::SubMenuHostDiscovery;
                        }
                        KeyCode::Char('2') => {
                            app.select(MainMenuItem::SubMenuPortScan);
                            app.state = AppState::SubMenuPortScan;
                        }
                        KeyCode::Char('3') => {
                            app.select(MainMenuItem::SubMenuServiceDetection);
                            app.state = AppState::IpAddressInput;
                        }
                        KeyCode::Char('4') => {
                            app.select(MainMenuItem::SubMenuOperatingSystemDetection);
                            app.state = AppState::IpAddressInput;
                        }
                        _ => {}
                    }
                }
                AppState::SubMenuHostDiscovery => {
                    match key.code {
                        KeyCode::Char('b') => {
                            app.state = AppState::MainMenu;
                            app.host_discovery_selected = None;
                        }
                        KeyCode::Char('q') => return Ok((None, None, None, "".to_string(), false, None, "".to_string())),
                        KeyCode::Char('1') => {
                            app.select_host_discovery(HostDiscoveryOption::ListScan);
                            app.state = AppState::IpAddressInput;
                        }
                        KeyCode::Char('2') => {
                            app.select_host_discovery(HostDiscoveryOption::PingScan);
                            app.state = AppState::IpAddressInput;
                        }
                        KeyCode::Char('3') => {
                            app.select_host_discovery(HostDiscoveryOption::TcpSynDiscovery);
                            app.state = AppState::IpAddressInput;
                            app.port_needed = true;
                        }
                        KeyCode::Char('4') => {
                            app.select_host_discovery(HostDiscoveryOption::TcpAckDiscovery);
                            app.state = AppState::IpAddressInput;
                            app.port_needed = true;
                        }
                        KeyCode::Char('5') => {
                            app.select_host_discovery(HostDiscoveryOption::UdpDiscovery);
                            app.state = AppState::IpAddressInput;
                            app.port_needed = true;
                        }
                        KeyCode::Char('6') => {
                            app.select_host_discovery(HostDiscoveryOption::ArpDiscovery);
                            app.state = AppState::IpAddressInput;
                            app.port_needed = true;
                        }
                        KeyCode::Char('7') => {
                            app.select_host_discovery(HostDiscoveryOption::IcmpEcho);
                            app.state = AppState::IpAddressInput;
                        }
                        KeyCode::Char('8') => {
                            app.select_host_discovery(HostDiscoveryOption::IcmpTimestamp);
                            app.state = AppState::IpAddressInput;
                        }
                        KeyCode::Char('9') => {
                            app.select_host_discovery(HostDiscoveryOption::IcmpNetmask);
                            app.state = AppState::IpAddressInput;
                        }
                        _ => {}
                    }
                }
                AppState::SubMenuPortScan => {
                    match key.code {
                        KeyCode::Char('b') => {
                            app.state = AppState::MainMenu;
                            app.port_scan_selected = None;
                        }
                        KeyCode::Char('q') => return Ok((None, None, None, "".to_string(), false, None, "".to_string())),
                        KeyCode::Char('1') => {
                            app.select_port_scan(PortScanOption::SynScan);
                            app.state = AppState::IpAddressInput;
                            app.port_needed = true;
                        }
                        KeyCode::Char('2') => {
                            app.select_port_scan(PortScanOption::ConnectScan);
                            app.state = AppState::IpAddressInput;
                            app.port_needed = true;
                        }
                        KeyCode::Char('3') => {
                            app.select_port_scan(PortScanOption::AckScan);
                            app.state = AppState::IpAddressInput;
                            app.port_needed = true;
                        }
                        KeyCode::Char('4') => {
                            app.select_port_scan(PortScanOption::WindowScan);
                            app.state = AppState::IpAddressInput;
                            app.port_needed = true;
                        }
                        KeyCode::Char('5') => {
                            app.select_port_scan(PortScanOption::MaimonScan);
                            app.state = AppState::IpAddressInput;
                            app.port_needed = true;
                        }
                        KeyCode::Char('6') => {
                            app.select_port_scan(PortScanOption::NullScan);
                            app.state = AppState::IpAddressInput;
                            app.port_needed = true;
                        }
                        KeyCode::Char('7') => {
                            app.select_port_scan(PortScanOption::FinScan);
                            app.state = AppState::IpAddressInput;
                            app.port_needed = true;
                        }
                        KeyCode::Char('8') => {
                            app.select_port_scan(PortScanOption::XmasScan);
                            app.state = AppState::IpAddressInput;
                            app.port_needed = true;
                        }
                        KeyCode::Char('9') => {
                            app.select_port_scan(PortScanOption::UdpScan);
                            app.state = AppState::IpAddressInput;
                            app.port_needed = true;
                        }
                        _ => {}
                    }
                }

                AppState::IpAddressInput => {
                    match key.code {
                        KeyCode::Enter => {
                            app.cursor_position = 0;
                            if app.port_needed {
                                app.state = AppState::PortOptions;
                            }
                            else {
                                return Ok((
                                    app.main_selected.clone(), 
                                    app.host_discovery_selected.clone(),
                                    app.port_scan_selected.clone(),
                                    app.ip_input.clone(),
                                    app.port_needed,
                                    app.port_mode.clone(),
                                    app.port_input.clone(),
                                ));
                            }
                        }
                        KeyCode::Char(c) => {
                            // Only allow characters valid for IP addresses
                            if c.is_digit(10) || c == '.' {
                                app.input_ip(c);
                            }
                        }
                        KeyCode::Backspace => {
                            app.delete_char_ip_input();
                        }
                        KeyCode::Left => {
                            app.move_cursor_left();
                        }
                        KeyCode::Right => {
                            app.move_cursor_right();
                        }
                        KeyCode::Esc => {
                            app.ip_input.clear();
                            app.cursor_position = 0;
                        }
                        _ => {}
                    }
                }

                AppState::PortOptions => {
                    match key.code {
                        KeyCode::Char('b') => {
                            app.state = AppState::MainMenu;
                            app.port_scan_selected = None;
                        }
                        KeyCode::Char('q') => return Ok((None, None, None, "".to_string(), false, None, "".to_string())),
                        KeyCode::Char('1') => {
                            app.port_mode = Some(PortOptions::NormalMode);
                            return Ok((
                                app.main_selected.clone(), 
                                app.host_discovery_selected.clone(),
                                app.port_scan_selected.clone(),
                                app.ip_input.clone(),
                                app.port_needed,
                                app.port_mode.clone(),
                                app.port_input.clone(),
                            ));
                        }
                        KeyCode::Char('2') => {
                            app.state = AppState::PortRangeInput;
                            app.port_mode = Some(PortOptions::PortRangeInput)
                        }
                        KeyCode::Char('3') => {
                            app.port_mode = Some(PortOptions::FastMode);
                            return Ok((
                                app.main_selected.clone(), 
                                app.host_discovery_selected.clone(),
                                app.port_scan_selected.clone(),
                                app.ip_input.clone(),
                                app.port_needed,
                                app.port_mode.clone(),
                                app.port_input.clone(),
                            ));

                        }
                        KeyCode::Char('4') => {
                            app.port_mode = Some(PortOptions::SequentialMode);
                            return Ok((
                                app.main_selected.clone(), 
                                app.host_discovery_selected.clone(),
                                app.port_scan_selected.clone(),
                                app.ip_input.clone(),
                                app.port_needed,
                                app.port_mode.clone(),
                                app.port_input.clone(),
                            ));
                        }
                        _ => {}
                    }
                }
                AppState::PortRangeInput => {
                    match key.code {
                        KeyCode::Enter => {
                                app.cursor_position = 0;
                                return Ok((
                                    app.main_selected.clone(), 
                                    app.host_discovery_selected.clone(),
                                    app.port_scan_selected.clone(),
                                    app.ip_input.clone(),
                                    app.port_needed,
                                    app.port_mode.clone(),
                                    app.port_input.clone(),
                                ));
                        }
                        
                        KeyCode::Char(c) => {
                            app.input_port(c);
                        }
                        KeyCode::Backspace => {
                            app.delete_char_port_range_input();
                        }
                        KeyCode::Left => {
                            app.move_cursor_left();
                        }
                        KeyCode::Right => {
                            app.move_cursor_right();
                        }
                        KeyCode::Esc => {
                            app.port_input.clear();
                            app.cursor_position = 0;
                        }
                        _ => {}
                    }
                }
    }
}

fn ui(f: &mut Frame, app: &App) {
    // Get full size of the frame
    let size = f.size();
    
    // First create a horizontal layout to center all elements at 25% width
    let horizontal_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage(0),   // Left margin
                Constraint::Percentage(25),   // Center content (25% width)
                Constraint::Percentage(0),   // Right margin
            ]
            .as_ref(),
        )
        .split(size);
    
    // Now create a vertical layout within the center horizontal section
    let vertical_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1) // Small margin within the 25% horizontal space
        .constraints(
            [
                Constraint::Length(3),       // Title
                Constraint::Min(10),         // Menu content
                Constraint::Length(3),       // Instructions
            ]
            .as_ref(),
        )
        .split(horizontal_layout[1]);
    
    // Center section for content
    let content_area = vertical_chunks[1];
    
    match app.state {
        AppState::MainMenu => {
            // Create title
            let title = Block::default()
                .title(
                    Span::styled(
                        "Onmap",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )
                )
                .borders(Borders::ALL);
            f.render_widget(title, vertical_chunks[0]);

            // Create menu items
            let items = vec![
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "1. Host discovery",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "2. Port scanning",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "3. Service detection",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "4. OS detection",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
            ];

            // Create menu list
            let menu_list = List::new(items)
                .block(Block::default().borders(Borders::ALL).title("Main Menu"))
                .highlight_style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                );
            f.render_widget(menu_list, content_area);

            // Create instructions
            let instructions = Block::default()
                .title("Instructions")
                .borders(Borders::ALL);

            // Add text to the instructions block
            let instructions_text = Text::from(
                "Press 1-4 to select an option. Press 'q' to quit."
            );
            f.render_widget(
                Paragraph::new(instructions_text).block(instructions),
                vertical_chunks[2],
            );
        }
        AppState::SubMenuHostDiscovery => {
            // Create title
            let title = Block::default()
                .title(
                    Span::styled(
                        "Host discovery",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )
                )
                .borders(Borders::ALL);
            f.render_widget(title, vertical_chunks[0]);

            // Create submenu items
            let sub_items = vec![
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "1. List scan (-sL)",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "2. Ping scan (-sn)",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "3. TCP SYN Discovery (-PS)",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "4. TCP ACK Discovery (-PA)",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "5. UDP Discovery (-PU)",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "6. ARP Discovery (-ARP)",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "7. ICMP echo (-PE)",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "8. ICMP timestamp (-PP)",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "9. ICMP netmask (-PM)",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
            ];

            // Create submenu list
            let submenu_list = List::new(sub_items)
                .block(Block::default().borders(Borders::ALL).title("Options"))
                .highlight_style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                );
            f.render_widget(submenu_list, content_area);

            // Create instructions
            let instructions = Block::default()
                .title("Instructions")
                .borders(Borders::ALL);

            // Add text to the instructions block
            let instructions_text = Text::from(
                "Press 1-9 to select a sub-option. Press 'b' to go back to main menu. Press 'q' to quit."
            );
            f.render_widget(
                Paragraph::new(instructions_text).block(instructions),
                vertical_chunks[2],
            );
        }
        AppState::SubMenuPortScan => {
            // Create title
            let title = Block::default()
                .title(
                    Span::styled(
                        "Port scanning",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )
                )
                .borders(Borders::ALL);
            f.render_widget(title, vertical_chunks[0]);

            // Create submenu items
            let sub_items = vec![
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "1. SYN scan (-sS)",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "2. Connect scan (-sT)",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "3. ACK scan (-sA)",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "4. Window scan (-sW)",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "5. Mainmon scan (-sM)",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "6. Null scan (-sN)",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "7. FIN scan (-sF)",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "8. Xmas scan (-sX)",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "9. UDP scan (-sU)",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
            ];

            // Create submenu list
            let submenu_list = List::new(sub_items)
                .block(Block::default().borders(Borders::ALL).title("Options"))
                .highlight_style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                );
            f.render_widget(submenu_list, content_area);

            // Create instructions
            let instructions = Block::default()
                .title("Instructions")
                .borders(Borders::ALL);

            // Add text to the instructions block
            let instructions_text = Text::from(
                "Press 1-9 to select a sub-option. Press 'b' to go back to main menu. Press 'q' to quit."
            );
            f.render_widget(
                Paragraph::new(instructions_text).block(instructions),
                vertical_chunks[2],
            );
        }
        AppState::IpAddressInput => {
            // Create title
            let title = Block::default()
                .title(
                    Span::styled(
                        "IP Address Input",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )
                )
                .borders(Borders::ALL);
            f.render_widget(title, vertical_chunks[0]);

            // Create input area
            let input = Paragraph::new(app.ip_input.as_str())
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().borders(Borders::ALL).title("Enter IP Address"));
            f.render_widget(input, content_area);
            
            // Show cursor at the current position
            f.set_cursor(
                // Add 1 for the border and 1 for the offset from the border
                content_area.x + app.cursor_position as u16 + 1,
                // Add 1 for the border and 1 for the offset from the border
                content_area.y + 1,
            );

            // Create instructions
            let instructions = Block::default()
                .title("Instructions")
                .borders(Borders::ALL);

            // Add text to the instructions block
            let instructions_text = Text::from(
                "Enter IP address and press Enter to submit. Press Esc to cancel."
            );
            f.render_widget(
                Paragraph::new(instructions_text).block(instructions),
                vertical_chunks[2],
            );
        }

        AppState::PortOptions => {
            // Create title
            let title = Block::default()
                .title(
                    Span::styled(
                        "Port scanning",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )
                )
                .borders(Borders::ALL);
            f.render_widget(title, vertical_chunks[0]);

            // Create submenu items
            let sub_items = vec![
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "1. Normal mode (all ports in a random order)",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "2. Port ranges (-p)",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "3. Fast mode (-F)",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
                ListItem::new(
                    Line::from(
                        Span::styled(
                            "4. Sequentially (-r)",
                            Style::default().fg(Color::White),
                        )
                    )
                ),
            ];

            // Create submenu list
            let submenu_list = List::new(sub_items)
                .block(Block::default().borders(Borders::ALL).title("Options"))
                .highlight_style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                );
            f.render_widget(submenu_list, content_area);

            // Create instructions
            let instructions = Block::default()
                .title("Instructions")
                .borders(Borders::ALL);

            // Add text to the instructions block
            let instructions_text = Text::from(
                "Press 1-3 to select a sub-option. Press 'b' to go back to main menu. Press 'q' to quit."
            );
            f.render_widget(
                Paragraph::new(instructions_text).block(instructions),
                vertical_chunks[2],
            );
        }

        AppState::PortRangeInput => {
            // Create title
            let title = Block::default()
                .title(
                    Span::styled(
                        "Port range input",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )
                )
                .borders(Borders::ALL);
            f.render_widget(title, vertical_chunks[0]);

            // Create input area
            let input = Paragraph::new(app.port_input.as_str())
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().borders(Borders::ALL).title("Enter Port range"));
            f.render_widget(input, content_area);
            
            // Show cursor at the current position
            f.set_cursor(
                // Add 1 for the border and 1 for the offset from the border
                content_area.x + app.cursor_position as u16 + 1,
                // Add 1 for the border and 1 for the offset from the border
                content_area.y + 1,
            );

            // Create instructions
            let instructions = Block::default()
                .title("Instructions")
                .borders(Borders::ALL);

            // Add text to the instructions block
            let instructions_text = Text::from(
                "Enter port range and press Enter to submit. Press Esc to cancel."
            );
            f.render_widget(
                Paragraph::new(instructions_text).block(instructions),
                vertical_chunks[2],
            );
        }
    }

    }
    }
}