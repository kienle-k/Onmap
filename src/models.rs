#[derive(Clone, Copy)]
pub enum AppState {
    MainMenu,
    SubMenuHostDiscovery,
    SubMenuPortScan,
    IpAddressInput,
    PortOptions,
    PortRangeInput
}

#[derive(Clone, Copy)]
pub enum MainMenuItem {
    SubMenuHostDiscovery,
    SubMenuPortScan,
    SubMenuServiceDetection,
    SubMenuOperatingSystemDetection,
}

/*
#[derive(Clone, Copy)]
pub enum AllMenuItem {
    SubMenuHostDiscovery,
    SubMenuPortScan,
    SubMenuServiceDetection,
    SubMenuOperatingSystemDetection,

    ListScan,
    PingScan,
    TcpSynDiscovery,
    TcpAckDiscovery,
    UdpDiscovery,
    ArpDiscovery,
    IcmpEcho,
    IcmpTimestamp,
    IcmpNetmask,

    SynScan,
    ConnectScan,
    AckScan,
    WindowScan,
    MaimonScan,
    NullScan,
    FinScan,
    XmasScan,
    UdpScan,
}
*/

#[derive(Clone, Copy)]
pub enum HostDiscoveryOption {
    ListScan,
    PingScan,
    TcpSynDiscovery,
    TcpAckDiscovery,
    UdpDiscovery,
    ArpDiscovery,
    IcmpEcho,
    IcmpTimestamp,
    IcmpNetmask,
}

#[derive(Clone, Copy)]
pub enum PortScanOption {
    SynScan,
    ConnectScan,
    AckScan,
    WindowScan,
    MaimonScan,
    NullScan,
    FinScan,
    XmasScan,
    UdpScan,
}

#[derive(Clone, Copy)]
pub enum PortOptions {
    NormalMode,
    PortRangeInput,
    FastMode,
    SequentialMode
}