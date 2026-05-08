# /mnt/derived/ raw image provenance

Source-of-truth record for raw disk images derived from the hackathon E01s.
Each entry lists the source artifact, conversion command, output size, and
MD5 hash of the raw output (so re-conversion is reproducible).

Updated 2026-05-08.

## SRL-2015 (SANS hackathon, Apr 2015 evidence)

Converted 2026-05-07 inside `sift-mcp` via `ewfexport -u -f raw`. Single
.raw output per host, multi-segment intermediates concatenated by:
`cat <prefix>.raw.raw.NN > <prefix>.raw && rm <prefix>.raw.raw.*`.
Conversion log: `/mnt/derived/_srl2015_convert.log`.
Concat log: `/mnt/derived/_srl2015_concat.log`.

| Output                                  | Size (bytes)   | Source E01                                                  | MD5                              |
|-----------------------------------------|----------------|-------------------------------------------------------------|----------------------------------|
| `xp-tdungan-c-drive.raw`                | 16,114,483,712 | `HACKATHON-2026/srl-2015/.../tdungan-c-drive.E01`           | 60b778a12a4b7ad5ed5b28eb6e869b3f |
| `win7-32-nromanoff-c-drive.raw`         | 26,578,255,872 | `HACKATHON-2026/srl-2015/.../nromanoff-c-drive.E01`         | e381e006d8b42042a3253c7e2f07ffb8 |
| `win7-64-nfury-c-drive.raw`             | 30,232,543,232 | `HACKATHON-2026/srl-2015/.../nfury-c-drive.E01`             | a98416e60bb81f57cb99125ec41bfe4c |
| `win2008R2-controller-c-drive.raw`      | 33,317,453,824 | `HACKATHON-2026/srl-2015/.../win2008R2-controller-c-drive.E01` | 3a33c416f0853f2c148a173f90363104 |

The Win2008R2 .E01 was originally extracted to a 5.4 GB all-zero file from
a corrupt MSYS unzip pass. After deletion, the SIFT container's Linux
unzip extracted a clean 14.3 GB .E01 from `Win2008R2-controller.zip` into
`/mnt/derived/_win2008_tmp/` (intermediate, removable).
Conversion log: `/mnt/derived/_win2008_convert.log`.

## OpenUni22 (Internet, single-host downloaded image)

| Output                              | Size (bytes)   | Source                                          | MD5                              |
|-------------------------------------|----------------|-------------------------------------------------|----------------------------------|
| `openuni22-server.raw`              | 53,687,091,200 | OpenUni22 download (full-disk dd image)         | 9a982399621826a66ff322cc87376e76 (from `.raw.info`) |
| `openuni22-server-cdrive.raw`       | 52,928,970,752 | C: partition slice of `openuni22-server.raw`    | (computed lazily; bytes equal `dd skip=206848 count=103376896` of the full raw) |

The full `openuni22-server.raw` is a multi-partition disk image (DOS
partition table). The first run of the pipeline against it failed at the
`fsstat_e01` step because the tool cannot fsstat a multi-partition raw.
`openuni22-server-cdrive.raw` is the C: partition slice (sector offset
206848, length 103,376,896 sectors @ 512 bytes), produced 2026-05-07 via:

```
dd if=/mnt/derived/openuni22-server.raw \
   of=/mnt/derived/openuni22-server-cdrive.raw \
   bs=512 skip=206848 count=103376896 status=progress
```

Extraction log: `/mnt/derived/_openuni22_partition_extract.log`.

## SRL-2018 base / dmz hosts

The base-* and dmz-ftp .ntfs.dd files in this directory were produced
earlier from SRL-2018 .E01 acquisitions. Their provenance lives in
`docs/reference/hackathon/dataset_manifest.md` (canonical SANS corpus
manifest); not duplicated here.
