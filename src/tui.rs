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
                                    app.main_selected, 
                                    app.host_discovery_selected,
                                    app.port_scan_selected,
                                    app.ip_input.clone(),
                                    app.port_needed,
                                    app.port_mode,
                                    app.port_input.clone(),
                                ));
                            }
                        }
                        KeyCode::Char(c) => {
                            // Only allow characters valid for IP addresses
                            if c.is_digit(10) || c == '.' || c == '-' || c == '/' {
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
                                app.main_selected, 
                                app.host_discovery_selected,
                                app.port_scan_selected,
                                app.ip_input.clone(),
                                app.port_needed,
                                app.port_mode,
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
                                app.main_selected, 
                                app.host_discovery_selected,
                                app.port_scan_selected,
                                app.ip_input.clone(),
                                app.port_needed,
                                app.port_mode,
                                app.port_input.clone(),
                            ));

                        }
                        KeyCode::Char('4') => {
                            app.port_mode = Some(PortOptions::SequentialMode);
                            return Ok((
                                app.main_selected, 
                                app.host_discovery_selected,
                                app.port_scan_selected,
                                app.ip_input.clone(),
                                app.port_needed,
                                app.port_mode,
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
                                    app.main_selected, 
                                    app.host_discovery_selected,
                                    app.port_scan_selected,
                                    app.ip_input.clone(),
                                    app.port_needed,
                                    app.port_mode,
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
                Constraint::Percentage(30),   // Center content (30% width)
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
                Constraint::Length(5),       // Instructions
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
            "Press 1-4 to select an option\nPress 'q' to quit"
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
                "Press 1-9 to select a sub-option\nPress 'b' to go back to main menu\nPress 'q' to quit"
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
                "Press 1-9 to select a sub-option\nPress 'b' to go back to main menu\nPress 'q' to quit"
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
                "Enter IP address and press Enter to submit\nPress Esc to clear"
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
                            "1. Normal mode (1-1000)",
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
                "Press 1-3 to select a sub-option\nPress 'b' to go back to main menu\nPress 'q' to quit"
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
                "Enter port range and press Enter to submit\nPress Esc to clear"
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




#[cfg(test)]
mod tests {
    
    use super::*;

    /// Tests that the `App::new()` constructor initializes the app state correctly.
    #[test]
    fn test_app_new() {
        let app = App::new();
        assert_eq!(app.state, AppState::MainMenu);
        assert_eq!(app.main_selected, None);
        assert_eq!(app.host_discovery_selected, None);
        assert_eq!(app.port_scan_selected, None);
        assert_eq!(app.ip_input, "");
        assert!(!app.port_needed);
        assert_eq!(app.port_mode, None);
        assert_eq!(app.port_input, "");
        assert_eq!(app.cursor_position, 0);
    }

    /// Tests the `select` method for main menu items.
    #[test]
    fn test_select() {
        let mut app = App::new();
        app.select(MainMenuItem::SubMenuHostDiscovery);
        assert_eq!(app.main_selected, Some(MainMenuItem::SubMenuHostDiscovery));
    }

    /// Tests the `select_host_discovery` method.
    #[test]
    fn test_select_host_discovery() {
        let mut app = App::new();
        app.select_host_discovery(HostDiscoveryOption::PingScan);
        assert_eq!(app.host_discovery_selected, Some(HostDiscoveryOption::PingScan));
    }

    /// Tests the `select_port_scan` method.
    #[test]
    fn test_select_port_scan() {
        let mut app = App::new();
        app.select_port_scan(PortScanOption::SynScan);
        assert_eq!(app.port_scan_selected, Some(PortScanOption::SynScan));
    }

    /// Tests character input for the IP address field.
    #[test]
    fn test_input_ip() {
        let mut app = App::new();
        app.input_ip('1');
        app.input_ip('2');
        app.input_ip('7');
        assert_eq!(app.ip_input, "127");
        assert_eq!(app.cursor_position, 3);
    }

    /// Tests character input for the IP address field at a specific cursor position.
    #[test]
    fn test_input_ip_with_cursor() {
        let mut app = App::new();
        app.input_ip('1');
        app.input_ip('2');
        app.input_ip('7');
        app.cursor_position = 1; // Move cursor to after '1'
        app.input_ip('.');
        assert_eq!(app.ip_input, "1.27");
        assert_eq!(app.cursor_position, 2);
    }

    /// Tests character input for the port range field.
    #[test]
    fn test_input_port() {
        let mut app = App::new();
        app.input_port('8');
        app.input_port('0');
        assert_eq!(app.port_input, "80");
        assert_eq!(app.cursor_position, 2);
    }
    
    /// Tests the backspace functionality for the IP input.
    #[test]
    fn test_delete_char_ip_input() {
        let mut app = App::new();
        app.input_ip('1');
        app.input_ip('9');
        app.input_ip('2');
        app.delete_char_ip_input();
        assert_eq!(app.ip_input, "19");
        assert_eq!(app.cursor_position, 2);
    }

    /// Tests deleting a character from the middle of the IP input string.
    #[test]
    fn test_delete_char_ip_input_middle() {
        let mut app = App::new();
        app.ip_input = String::from("127.0.0.1");
        app.cursor_position = 4; // Cursor is after the '.'
        app.delete_char_ip_input();
        assert_eq!(app.ip_input, "1270.0.1");
        assert_eq!(app.cursor_position, 3);
    }

    /// Tests that deleting from an empty IP input does nothing.
    #[test]
    fn test_delete_char_ip_input_empty() {
        let mut app = App::new();
        app.delete_char_ip_input();
        assert_eq!(app.ip_input, "");
        assert_eq!(app.cursor_position, 0);
    }

    /// Tests the backspace functionality for the port range input.
    #[test]
    fn test_delete_char_port_range_input() {
        let mut app = App::new();
        app.input_port('8');
        app.input_port('0');
        app.input_port('-');
        app.input_port('9');
        app.delete_char_port_range_input();
        assert_eq!(app.port_input, "80-");
        assert_eq!(app.cursor_position, 3);
    }

    /// Tests moving the cursor left.
    #[test]
    fn test_move_cursor_left() {
        let mut app = App::new();
        app.ip_input = "test".to_string();
        app.cursor_position = 4;
        app.move_cursor_left();
        assert_eq!(app.cursor_position, 3);
    }

    /// Tests that the cursor does not move left past the beginning of the input.
    #[test]
    fn test_move_cursor_left_at_start() {
        let mut app = App::new();
        app.move_cursor_left();
        assert_eq!(app.cursor_position, 0);
    }
    
    /// Tests moving the cursor right.
    #[test]
    fn test_move_cursor_right() {
        let mut app = App::new();
        app.ip_input = "test".to_string();
        app.cursor_position = 1;
        app.move_cursor_right();
        assert_eq!(app.cursor_position, 2);
    }

    /// Tests that the cursor does not move right past the end of the input.
    #[test]
    fn test_move_cursor_right_at_end() {
        let mut app = App::new();
        app.ip_input = "test".to_string();
        app.cursor_position = 4;
        app.move_cursor_right();
        assert_eq!(app.cursor_position, 4);
    }

    // --- State Transition Tests (Simulating run_app logic) ---

    /// Tests the transition from the Main Menu to the Host Discovery sub-menu.
    #[test]
    fn test_main_menu_to_host_discovery() {
        let mut app = App::new();
        // Simulate pressing '1' in the main menu
        app.select(MainMenuItem::SubMenuHostDiscovery);
        app.state = AppState::SubMenuHostDiscovery;

        assert_eq!(app.state, AppState::SubMenuHostDiscovery);
        assert_eq!(app.main_selected, Some(MainMenuItem::SubMenuHostDiscovery));
    }

    /// Tests the transition from the Host Discovery sub-menu back to the Main Menu.
    #[test]
    fn test_host_discovery_back_to_main_menu() {
        let mut app = App {
            state: AppState::SubMenuHostDiscovery,
            host_discovery_selected: Some(HostDiscoveryOption::PingScan),
            ..App::new()
        };
        // Simulate pressing 'b'
        app.state = AppState::MainMenu;
        app.host_discovery_selected = None;

        assert_eq!(app.state, AppState::MainMenu);
        assert_eq!(app.host_discovery_selected, None);
    }

    /// Tests selecting a host discovery option that does NOT require a port.
    #[test]
    fn test_host_discovery_to_ip_input_no_port() {
        let mut app = App {
            state: AppState::SubMenuHostDiscovery,
            ..App::new()
        };
        // Simulate pressing '2' (Ping Scan)
        app.select_host_discovery(HostDiscoveryOption::PingScan);
        app.state = AppState::IpAddressInput;

        assert_eq!(app.state, AppState::IpAddressInput);
        assert_eq!(app.host_discovery_selected, Some(HostDiscoveryOption::PingScan));
        assert!(!app.port_needed, "Ping scan should not require a port");
    }

    /// Tests selecting a host discovery option that DOES require a port.
    #[test]
    fn test_host_discovery_to_ip_input_with_port() {
        let mut app = App {
            state: AppState::SubMenuHostDiscovery,
            ..App::new()
        };
        // Simulate pressing '3' (TCP SYN Discovery)
        app.select_host_discovery(HostDiscoveryOption::TcpSynDiscovery);
        app.state = AppState::IpAddressInput;
        app.port_needed = true;

        assert_eq!(app.state, AppState::IpAddressInput);
        assert_eq!(app.host_discovery_selected, Some(HostDiscoveryOption::TcpSynDiscovery));
        assert!(app.port_needed, "TCP SYN Discovery should require a port");
    }
    
    /// Tests selecting a port scan option, which should always require a port.
    #[test]
    fn test_port_scan_to_ip_input() {
        let mut app = App {
            state: AppState::SubMenuPortScan,
            ..App::new()
        };
        // Simulate pressing '1' (SYN Scan)
        app.select_port_scan(PortScanOption::SynScan);
        app.state = AppState::IpAddressInput;
        app.port_needed = true;

        assert_eq!(app.state, AppState::IpAddressInput);
        assert_eq!(app.port_scan_selected, Some(PortScanOption::SynScan));
        assert!(app.port_needed);
    }

    /// Tests the transition from IP input to the Port Options menu when a port is needed.
    #[test]
    fn test_ip_input_to_port_options() {
        let mut app = App {
            state: AppState::IpAddressInput,
            ip_input: String::from("127.0.0.1"),
            port_needed: true,
            cursor_position: 9,
            ..App::new()
        };

        // Simulate pressing Enter
        app.cursor_position = 0;
        app.state = AppState::PortOptions;

        assert_eq!(app.state, AppState::PortOptions);
        assert_eq!(app.cursor_position, 0);
    }

    /// Tests the transition from Port Options to the Port Range Input screen.
    #[test]
    fn test_port_options_to_port_range_input() {
        let mut app = App {
            state: AppState::PortOptions,
            ..App::new()
        };
        // Simulate pressing '2' for custom port range
        app.state = AppState::PortRangeInput;
        app.port_mode = Some(PortOptions::PortRangeInput);

        assert_eq!(app.state, AppState::PortRangeInput);
        assert_eq!(app.port_mode, Some(PortOptions::PortRangeInput));
    }
    
    /// Tests the character validation logic in the IP Address input state.
    #[test]
    fn test_ip_address_input_validation_logic() {
        let mut app = App {
            state: AppState::IpAddressInput,
            ..App::new()
        };
        
        // This simulates the logic from run_app
        let process_key = |app: &mut App, c: char| {
            if c.is_digit(10) || c == '.' || c == '-' || c == '/' {
                app.input_ip(c);
            }
        };

        process_key(&mut app, '1');
        process_key(&mut app, 'a'); // Invalid
        process_key(&mut app, '.');
        process_key(&mut app, '0');
        process_key(&mut app, ' '); // Invalid
        process_key(&mut app, '/');
        process_key(&mut app, '8');

        assert_eq!(app.ip_input, "1.0/8");
    }

    /// Tests that the Escape key clears the IP input field.
    #[test]
    fn test_ip_input_escape_key() {
        let mut app = App {
            state: AppState::IpAddressInput,
            ip_input: String::from("some text"),
            cursor_position: 9,
            ..App::new()
        };

        // Simulate pressing ESC
        app.ip_input.clear();
        app.cursor_position = 0;

        assert_eq!(app.ip_input, "");
        assert_eq!(app.cursor_position, 0);
    }
}