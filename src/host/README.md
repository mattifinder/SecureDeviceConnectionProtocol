sdcpusb
=====

`sdcpusb` runs the host side of SDCP against a Kensington VeriMark Desktop 2.0
(USB `047d:8228`), or against a simulated device built on `libsdcpcli`
(`--mock`).

```
sdcpusb connect reconnect identify          # one session, three steps
sdcpusb --session s.bin connect             # keep the session for later runs
sdcpusb --session s.bin identify
sdcpusb --mock connect identify             # no hardware needed
sdcpusb --mock-tamper model-sig connect     # must fail
```

Behaviour that follows the Windows driver
-----

The checks below mirror Realtek's WinBio adapter (`AtansMocAdapter.dll`,
DriverVer 10.103.22621.143), which the Windows driver package for this device
installs.

### Model certificate

The device sends only its model certificate (the leaf). The adapter accepts
the device only if that leaf is byte for byte one of a few embedded
certificates, and adds the two intermediates itself. `sdcpusb` does the same
with the table in `modelcerts.c`, before any key agreement:

| Leaf | Intermediates | Accepted |
|---|---|---|
| RTS5813, 2023-02-16 to 2024-05-16 | Windows Hello 11B0C61D CA 2021, Windows Hello Secure Devices PCA 2018 | always |
| RTS5816, 2024-05-16 to 2025-08-16 (sent by the VeriMark) | same | always |
| model 46D3B003, 2018-05-24 to 2019-08-24 | Windows Hello 19B92965 CA 2018, Windows Hello Secure Devices PCA 2018 | `--legacy-model` (the adapter's `AutoDetect` registry value) |

The model and vendor in each leaf's subject alternative name are GUID-shaped
ASCII: `52545335-3831-3600-…` is `"RTS5816"`, `5265616C-7465-6B00-…` is
`"Realtek"`.

- `--any-model-cert` accepts other certificates (other devices).
- `--ca FILE` additionally validates the chain up to the roots in `FILE`. With
  a pinned leaf the built-in intermediates are used, so `FILE` only needs the
  root (Microsoft ECC Devices Root CA 2017).
- All three leaves have expired, and Windows still accepts the VeriMark. An
  expired certificate is therefore only a warning; `--strict-validity` makes
  it an error.
- `--mock` accepts the bare public key the simulated device sends in place of
  a certificate. Without `--mock` a bare key is refused.

The claim is split the way the adapter does it: the certificate is the claim
minus the fixed 290-byte tail (`pk_d ‖ pk_f ‖ h_f ‖ s_m ‖ s_d`), and its DER
header must agree.

### Identify result

The 0x4a-byte identify result is `status ‖ sub_factor ‖ id(32) ‖ m(32) ‖ trailer(8)`:

| status | Meaning |
|---|---|
| `0x00` | match; `sub_factor` is the finger (WINBIO ANSI 381 position, 1–5 right thumb to little, 6–10 left) |
| `0x0b` | no match |
| `0x0c` | rejected, reported as reject detail 8 (too skewed) |
| other | rejected, the status is the reject detail |

Only `id` is covered by the MAC. The adapter keeps the 8-byte trailer, but its
meaning is unknown. On a match, Windows identifies the template by the 32-byte
`id` (a WinBio SecureId).

### Who verifies what on Windows

The adapter does not verify the SDCP claim, MACs or signatures; the Windows
biometric service does. The adapter selects the model chain, forwards the
device's answers and adds the intermediate certificates. `sdcpusb` performs
the service's checks itself: claim MAC, model signature over `pk_d`, device
signature over `C0 01 ‖ h_f ‖ pk_f`, reconnect MAC and identify MAC.

The adapter also contains a copy of this repository's `sdcpcli` from its first
commit, but never calls it.

Regenerating modelcerts.c
-----

The certificates are taken from `AtansMocAdapter.dll` at the file offsets
noted next to each array, which also records its SHA-256. Each array is the
complete DER `SEQUENCE` starting at that offset.
