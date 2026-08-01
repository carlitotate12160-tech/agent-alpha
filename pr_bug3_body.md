## BUG 3 — frameset/iframe href extraction

Frameset sites carry navigation in `<frame src>` / `<iframe src>`, not `<a href>`. The `<a>`-only regex in `_extract_hrefs` returned 0 links on frameset homepages, leaving the entire site invisible to recon.

### Fix
Extended regex to match both `a href` and `i?frame src` (case-insensitive). Same-origin filter unchanged — cross-origin iframe src still rejected.

### Tests
3 new tests in `test_frontier_expansion.py`:
- `test_extract_hrefs_frameset_extracts_frame_and_iframe_src` — frame + iframe src → links
- `test_extract_hrefs_frameset_drops_cross_origin_src` — evil.com iframe src rejected
- `test_extract_hrefs_frame_src_uppercase_and_attr_before_src` — uppercase tags + attr order

17/17 pass. No regressions.
