fn main() {
    println!("cargo:rerun-if-changed=keyhole.rc");
    println!("cargo:rerun-if-changed=keyhole.manifest");
    println!("cargo:rerun-if-changed=assets/keyhole.ico");
    embed_resource::compile("keyhole.rc", embed_resource::NONE)
        .manifest_required()
        .unwrap();
    let config = slint_build::CompilerConfiguration::new().with_style("fluent-dark".into());
    slint_build::compile_with_config("ui/app.slint", config).unwrap();
}
