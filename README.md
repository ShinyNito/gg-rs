# gg-rs 🚀


## 🌟 Project Features

- **Easily Proxy**: Easily set up a proxy for any Linux command, streamlining the process of proxying network requests.
- **Designed for Linux**: Tailored for Linux users, ensuring a smooth experience in a Linux environment.

## ⚠️ Usage Note

`gg-rs` is in its early development stage, primarily meant for learning and research purposes. It is currently not recommended for production use. At this stage, `gg-rs` supports only the Shadowsocks proxy protocol, with plans to include more protocols in the future.

## 🛠️ Installation and Usage

Ensure you have a Rust environment set up on your device:

```sh
git clone https://github.com/your-github-username/gg-rs.git
cd gg-rs
cargo build --release
```

### Example Usage

Using `gg-rs` is straightforward; prepend your command with `gg-rs -p <ss local port>`:

```sh
gg-rs -p 1080 curl http://google.com
```

This command executes `curl http://google.com` through a Shadowsocks proxy listening on the local port 1080.

## 📝 License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## 💡 Acknowledgments

- Inspiration: [gg](https://github.com/mzz2017/gg)
- Shadowsocks Rust Implementation: [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)
- The Rust Programming Language
