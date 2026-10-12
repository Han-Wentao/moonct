// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html
//
// To add a dependency, run this command in your terminal:
//   moon add moonbitlang/x
//
// Or manually declare it in `import`, for example:
// import {
//   "moonbitlang/x@0.4.6",
// }

name = "Han-Wentao/moonct"

version = "0.2.0"

readme = "README.md"

repository = "https://github.com/Han-Wentao/moonct"

license = "Apache-2.0"

keywords = [
  "certificate-transparency",
  "merkle",
  "security",
  "proof-verification",
  "json",
  "codec",
]

preferred_target = "wasm"

description = "RFC 6962 and RFC 9162 Certificate Transparency proof core for MoonBit"
