fn main() {
    #[cfg(windows)]
    {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/packetatlas.ico");
        res.set("ProductName", "PacketAtlas");
        res.set(
            "FileDescription",
            "PacketAtlas — Network Traffic Monitor & OSINT Geo-Telemetry",
        );
        if let Err(e) = res.compile() {
            println!("cargo:warning=Failed to embed Windows icon resource: {}", e);
        }
    }
}
