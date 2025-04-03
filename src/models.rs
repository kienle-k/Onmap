#[derive(Clone)]
pub enum AppState {
    MainMenu,
    SubMenuHostDiscovery,
    SubMenuPortScan,
    IpAddressInput,
    PortOptions,
    PortRangeInput
}

#[derive(Clone)]
pub enum MainMenuItem {
    SubMenuHostDiscovery,
    SubMenuPortScan,
    SubMenuServiceDetection,
    SubMenuOperatingSystemDetection,
}

/*
#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
pub enum PortOptions {
    PortRangeInput,
    FastMode,
    SequentialMode
}