fn main() {
    #[cfg(windows)]
    {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/glasstrace.ico");
        res.set("ProductName", "GlassTrace Desktop");
        res.set(
            "FileDescription",
            "GlassTrace Desktop — Network Traffic Monitor & OSINT Geo-Telemetry",
        );
        if let Err(e) = res.compile() {
            println!("cargo:warning=Failed to embed Windows icon resource: {}", e);
        }
    }
}
