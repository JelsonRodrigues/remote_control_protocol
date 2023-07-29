pub const ADDRESS:std::net::Ipv4Addr = std::net::Ipv4Addr::LOCALHOST;
pub const PORT_CLIENT:u16 = 5823;
pub const PORT_SERVER:u16 = 5824;
pub const BUFFER_SIZE:usize = 1 << 14;
pub const CLIENT_ADDR_SOCKET: std::net::SocketAddrV4 = std::net::SocketAddrV4::new(ADDRESS, PORT_CLIENT);
pub const SERVER_ADDR_SOCKET: std::net::SocketAddrV4 = std::net::SocketAddrV4::new(ADDRESS, PORT_SERVER);