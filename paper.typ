#import "@preview/charged-ieee:0.1.4": ieee

#show: ieee.with(
  title: [Systematic Classification and Trend Analysis of Baseband Modem CVEs Across Major Chipset Vendors],
  abstract: [
    We present an empirical analysis of publicly disclosed Common Vulnerabilities and Exposures (CVEs)
    affecting cellular baseband modem firmware across five chipset vendors: Qualcomm, Samsung (Exynos),
    MediaTek, Unisoc, and Apple. A corpus of 320 CVEs spanning 2010 to 2026 was collected from the
    National Vulnerability Database, enriched with manually curated protocol annotations, and classified
    by radio-access-technology subsystem and impact severity. The results show that 4G/LTE and 5G/NR
    subsystems account for the largest share of labelled vulnerabilities, that Remote Code Execution and
    memory-corruption-class bugs appear consistently across all vendors, and that disclosure volume
    accelerated sharply from 2022 onward driven by maturing modem security research tooling
    @firmwire_ndss2022 @lisowski_usenix2024 @overcoming_state @otabase and by concentrated vendor advisory cycles
    @p0_exynos_2023 @samsung_psu @mediatek_psb. Approximately 29.7% of CVEs could not be assigned a
    specific protocol label from public descriptions alone, highlighting a systemic transparency gap in
    vendor advisories.
  ],
  authors: (
    (
      name: "",
      department: [],
      organization: [],
      location: [--],
      email: "",
    ),
  ),
  index-terms: (),
  bibliography: bibliography("refs.bib"),
)

#let sub-c = (
  "2G":           rgb("#2196F3"),
  "3G":           rgb("#64B5F6"),
  "4G/LTE":       rgb("#4CAF50"),
  "5G/NR":        rgb("#EF5350"),
  "IMS":          rgb("#FF9800"),
  "SMS":          rgb("#E91E63"),
  "SIM":          rgb("#9C27B0"),
  "Upper Levels": rgb("#00BCD4"),
  "Local":        rgb("#607D8B"),
  "Multi-RAT":    rgb("#FFC107"),
  "Unknown":      rgb("#BDBDBD"),
)
#let imp-c = (
  "RCE":     rgb("#D32F2F"),
  "PrivEsc": rgb("#7B1FA2"),
  "RCE/DoS": rgb("#E65100"),
  "DoS":     rgb("#388E3C"),
)
#let ven-c = (
  "Apple":    rgb("#9E9E9E"),
  "MediaTek": rgb("#EF5350"),
  "Qualcomm": rgb("#1565C0"),
  "Samsung":  rgb("#2E7D32"),
  "Unisoc":   rgb("#4527A0"),
)

// ── Typography shortcuts ──────────────────────────────────────────────────────
#let fs-lbl  = 7pt
#let fs-tick = 6.5pt
#let fs-cap  = 7.5pt
#let lbl(t)  = text(size: fs-lbl, t)
#let tck(t)  = text(size: fs-tick, fill: rgb("#444444"), t)
#let cap(n, t) = {
  v(2pt)
  align(center, text(size: fs-cap, style: "italic")[Fig. #n. #t])
  v(5pt)
}
#let sec(t) = {
  v(6pt)
  align(center, text(size: 8.5pt, weight: "bold", smallcaps(t)))
  v(3pt)
}

// ── Bar height & spacing ──────────────────────────────────────────────────────
#let BH = 7pt    // bar height
#let RG = 1.5pt  // row gap

// ── Primitives ────────────────────────────────────────────────────────────────

// Simple horizontal bar row
#let hbar(label, n, max-n, col, total: 320) = {
  let pct = calc.round(n / total * 100, digits: 1)
  grid(
    columns: (46pt, 1fr, 20pt, 22pt),
    column-gutter: 4pt,
    align: (right + horizon, left + horizon, right + horizon, right + horizon),
    lbl(label),
    box(width: 100%, height: BH, fill: rgb("#EEEEEE"), radius: 1pt, clip: true,
      align(left, box(width: n / max-n * 100%, height: BH, fill: col, radius: 1pt))
    ),
    tck(str(n)),
    tck(str(pct) + "%"),
  )
  v(RG)
}

// 100% stacked horizontal bar row
// segs: array of (n, color, short-label)
#let sbar(row-lbl, segs, row-col: rgb("#555555")) = {
  let total = segs.fold(0, (a, s) => a + s.at(0))
  grid(
    columns: (46pt, 1fr, 18pt),
    column-gutter: 4pt,
    align: (right + horizon, left + horizon, right + horizon),
    lbl(row-lbl),
    box(
      width: 100%, height: BH + 1pt,
      stroke: stroke(paint: rgb("#BBBBBB"), thickness: 0.3pt),
      radius: 1pt, clip: true,
      stack(dir: ltr,
        ..segs.map(s => {
          let (n, col, _) = s
          let w = if total > 0 { n / total * 100% } else { 0% }
          box(width: w, height: BH + 1pt, fill: col)
        })
      )
    ),
    tck(str(total)),
  )
  v(RG)
}

// Compact legend  (items: array of (label, color))
#let lgd(items, cols: 5) = {
  set text(size: 6.5pt)
  grid(
    columns: (auto,) * calc.min(cols, items.len()),
    column-gutter: 7pt, row-gutter: 2pt,
    ..items.map(it =>
      box(
        box(width: 7pt, height: 7pt, fill: it.at(1), radius: 1pt) +
        h(2.5pt) + it.at(0)
      )
    )
  )
  v(3pt)
}

= Introduction

Cellular baseband modems implement a complex layered stack spanning physical-layer radio control up
through SIP-based voice services. Because baseband processors run proprietary firmware that processes
untrusted over-the-air data, vulnerabilities in this layer can be exploited remotely without any
interaction from the device owner. Weinmann's early work @woot12_weinmann demonstrated that memory
corruption in legacy GSM and UMTS stacks was exploitable from a rogue base station, and subsequent
research has confirmed that pre-authentication Remote Code Execution remains achievable across 4G/LTE
and 5G/NR on commercial chipsets @p0_exynos_2023 @taszk_there_will_be_bugs.

Research tooling has matured considerably over the same period. FirmWire @firmwire_ndss2022 and BaseBridge
@samsung_cve_2024_20039 enabled
emulation-based dynamic analysis of baseband firmware without physical hardware.
Fuzzing campaigns followed: SIMurai @lisowski_usenix2024 exposed the SIM card as a
previously overlooked attack vector against baseband firmware, discovering two high-severity
vulnerabilities via SIM-originated fuzzing; Goos and Muench @overcoming_state fuzzed Layer-2
protocol state machines; and Tu et al. @logic_gone performed a security analysis of 5G baseband
control-plane protocols. These advances, combined with coordinated disclosure programmes at Samsung
@samsung_psu, MediaTek @mediatek_psb, and Qualcomm, have driven a sharp increase in public CVE
volume since 2022.

Despite the severity and growing volume of these vulnerabilities, no publicly available dataset
systematically covers the full landscape of disclosed baseband CVEs across vendors, protocol layers,
and impact categories over time. This paper presents such a dataset, constructed by scraping and
parsing CVE records from OpenCVE and vendor advisory pages, enriching them with manually curated
protocol annotations, and classifying each entry by subsystem and impact tier. The classification
pipeline and scraping methodology are described in the appendices for reproducibility; the body of
the paper focuses on the empirical findings.

= Results

The full corpus comprises 320 CVEs spanning 2010 to 2026, distributed across five vendors: Qualcomm (108, 33.8%), MediaTek (88, 27.5%), Samsung (85, 26.6%), Unisoc (37, 11.6%), and Apple (2, 0.6%). By impact, DoS accounts for 189 CVEs (59.1%), RCE/DoS for 80 (25.0%), confirmed RCE for 45 (14.1%), and PrivEsc for 6 (1.9%). The ten subsystem labels assigned to CVEs are detailed in @tab:taxonomy; 95 CVEs (29.7%) could not be assigned any label and fall into the Unknown category.

= Methodology

All CVE records were collected from the raw NVD-format CVE JSON (@appendix:scraping), the collected records for each vendor are then written to a dedicated JSON file and are augmented with additional information and descriptions gathered manually, they are then the sole input to the classification and visualisation
pipeline.

Each CVE description is mapped to one or more of the ten subsystem labels shown in @tab:taxonomy based on the provided description and is tested
against a list of over 130 compiled regular expressions. Each pattern maps to a
four-element hierarchy tuple of domain, sublayer, component, and detail. In this paper only the first element of this classification is used to classify the CVEs according to the subsystem they belong to. A CVE matching
multiple subsystems is marked as Multi-RAT. A more detailed development about the classification of the subsystems is available at @appendix:rat.

To classify the impact of a CVE we use a hybrid approach, the description and the CWE of a CVE are both checked against compiled regular expressions in order to match the apparent outcome of the bug (@tab:impact). But given the description might be misleading we gathered additional information about the CVEs and about their exploitability which allows us to manually associate a known income to a specific set of vulnerabilities.

== Temporal Distribution by Impact

// Monthly data: (year-as-float, rce, privesc, rcedos, dos)
// Derived from CVEs BY MONTH × IMPACT
#let months = (
  (2010.0,   1,0,0,0),
  (2017.25,  0,0,0,1),
  (2018.25,  0,0,0,1),
  (2018.5,   0,0,1,1),
  (2018.75,  0,0,1,1),
  (2018.833, 0,0,0,1),
  (2019.0,   0,0,0,2),
  (2019.083, 0,0,0,1),
  (2019.667, 0,0,0,1),
  (2019.833, 0,0,0,1),
  (2020.0,   1,0,1,0),
  (2020.167, 0,0,1,1),
  (2020.583, 0,0,0,1),
  (2020.833, 0,0,0,1),
  (2021.0,   2,0,4,0),
  (2021.167, 0,0,1,1),
  (2021.333, 0,0,0,1),
  (2021.5,   0,0,1,0),
  (2021.667, 4,0,0,0),
  (2021.75,  0,1,1,3),
  (2021.833, 0,0,1,0),
  (2022.0,   1,0,0,1),
  (2022.5,   2,0,0,0),
  (2022.667, 0,0,0,1),
  (2022.833, 1,0,0,4),
  (2022.917, 2,0,0,8),
  (2023.0,   1,0,1,1),
  (2023.083, 0,0,3,7),
  (2023.167, 9,0,4,4),
  (2023.25,  1,0,14,16),
  (2023.333, 0,0,4,9),
  (2023.417, 0,0,1,5),
  (2023.5,   0,0,2,1),
  (2023.667, 0,0,1,4),
  (2023.75,  1,0,1,4),
  (2023.833, 2,1,0,0),
  (2023.917, 0,0,1,9),
  (2024.0,   1,0,5,3),
  (2024.083, 0,0,0,3),
  (2024.167, 0,0,1,0),
  (2024.25,  1,0,1,4),
  (2024.417, 0,0,3,4),
  (2024.5,   1,0,3,3),
  (2024.583, 1,0,0,0),
  (2024.667, 0,0,1,2),
  (2024.75,  0,0,1,1),
  (2024.833, 0,0,1,2),
  (2024.917, 1,3,0,1),
  (2025.0,   2,1,0,5),
  (2025.083, 1,0,0,1),
  (2025.167, 0,0,3,1),
  (2025.25,  0,0,0,1),
  (2025.333, 0,0,5,3),
  (2025.5,   0,0,1,1),
  (2025.667, 2,0,0,2),
  (2025.75,  1,0,1,3),
  (2025.833, 3,0,0,1),
  (2025.917, 0,0,2,23),
  (2026.0,   0,0,2,6),
  (2026.083, 0,0,3,7),
  (2026.167, 1,0,0,8),
  (2026.25,  2,0,2,6),
  (2026.333, 0,0,1,6),
)

#let t-min = 2010.0
#let t-max = 2026.5
#let y-max = 32   // slightly above peak of 31

#let W = 8.1cm
#let H = 5.8cm
#let pad-l = 0.75cm
#let pad-b = 0.65cm
#let pad-t = 0.1cm
#let pad-r = 0.1cm

#let plot-w = W - pad-l - pad-r
#let plot-h = H - pad-b - pad-t

#let tx(t) = pad-l + (t - t-min) / (t-max - t-min) * plot-w
// bar width: roughly 1 month wide
#let bar-w = plot-w / ((t-max - t-min) * 12) * 0.82
#let ty(y) = pad-t + plot-h - y / y-max * plot-h

#let y-ticks = (0, 5, 10, 15, 20, 25, 30)
#let x-ticks = (2012, 2014, 2016, 2018, 2020, 2022, 2024, 2026)

#lgd((("DoS", imp-c.DoS), ("RCE/DoS", imp-c.at("RCE/DoS")), ("RCE", imp-c.RCE), ("PrivEsc", imp-c.PrivEsc)), cols: 4)

#box(width: W, height: H, {
  // gridlines + y labels
  for yt in y-ticks {
    let y = ty(yt)
    place(dx: pad-l, dy: y,
      line(length: plot-w, stroke: rgb("#E8E8E8") + 0.4pt))
    place(dx: 0pt, dy: y - 3.5pt,
      box(width: pad-l - 2pt, align(right, tck(str(yt)))))
  }

  // x-axis ticks + labels
  for xt in x-ticks {
    let x = tx(float(xt))
    place(dx: x, dy: pad-t + plot-h,
      line(length: 3pt, angle: 90deg, stroke: rgb("#999") + 0.4pt))
    place(dx: x - 8pt, dy: pad-t + plot-h + 3.5pt,
      box(width: 16pt, align(center, tck(str(xt)))))
  }

  // axes
  place(dx: pad-l, dy: pad-t,
    line(start: (0pt, plot-h), end: (plot-w, plot-h), stroke: rgb("#555") + 0.5pt))
  place(dx: pad-l, dy: pad-t,
    line(start: (0pt, 0pt), end: (0pt, plot-h), stroke: rgb("#555") + 0.5pt))

  // stacked bars — draw DoS bottom, then RCE/DoS, then RCE, then PrivEsc on top
  for m in months {
    let (t, rce, priv, rdos, dos) = m
    let x = tx(t) - bar-w / 2
    let segs = (
      (dos,  imp-c.DoS),
      (rdos, imp-c.at("RCE/DoS")),
      (rce,  imp-c.RCE),
      (priv, imp-c.PrivEsc),
    )
    let y-cur = 0
    for (n, col) in segs {
      if n > 0 {
        let y-bot = ty(y-cur + n)
        let y-top = ty(y-cur)
        let h = y-top - y-bot
        place(dx: x, dy: y-bot,
          rect(width: bar-w, height: h, fill: col, stroke: none))
        y-cur = y-cur + n
      }
    }
  }
})

#cap(3, [Monthly CVE counts stacked by impact. Peak of 31 in April 2023.])

Disclosure volume was consistently low at one to three CVEs per month from 2010 through 2021
. A sustained acceleration begins in mid-2022 and culminates in a peak of 31 CVEs
in April 2023, corresponding to the Project Zero batch of 18 internet-to-baseband RCE vulnerabilities
in Exynos modems disclosed by Project Zero @p0_exynos_2023. A secondary peak of 25 CVEs appears in
December 2025, attributable to coordinated MediaTek and Qualcomm advisory cycles
@mediatek_psb_dec2025. The dominant impact across almost all months is DoS. As the number of CVEs increases, the amount of RCE/DoS and RCE labelled bugs increase significantly too, being roughly half of the disclosed bugs in the start of 2023.

== Cumulative Discovery per Vendor

#let monthly = (
  (2010.0 +  0/12, 1, 0, 0,  0,  0),
  (2017.0 +  3/12, 0, 0, 0,  1,  0),
  (2018.0 +  3/12, 0, 0, 1,  0,  0),
  (2018.0 +  6/12, 0, 0, 2,  0,  0),
  (2018.0 +  9/12, 0, 0, 2,  0,  0),
  (2018.0 + 10/12, 0, 0, 1,  0,  0),
  (2019.0 +  0/12, 0, 0, 2,  0,  0),
  (2019.0 +  1/12, 0, 0, 1,  0,  0),
  (2019.0 +  8/12, 0, 0, 1,  0,  0),
  (2019.0 + 10/12, 0, 0, 1,  0,  0),
  (2020.0 +  0/12, 0, 0, 1,  1,  0),
  (2020.0 +  2/12, 0, 0, 0,  2,  0),
  (2020.0 +  7/12, 0, 0, 0,  1,  0),
  (2020.0 + 10/12, 0, 0, 1,  0,  0),
  (2021.0 +  0/12, 0, 4, 0,  2,  0),
  (2021.0 +  2/12, 0, 0, 2,  0,  0),
  (2021.0 +  4/12, 0, 0, 1,  0,  0),
  (2021.0 +  6/12, 0, 0, 1,  0,  0),
  (2021.0 +  8/12, 0, 4, 0,  0,  0),
  (2021.0 +  9/12, 0, 1, 1,  3,  0),
  (2021.0 + 10/12, 0, 0, 1,  0,  0),
  (2022.0 +  0/12, 0, 1, 0,  1,  0),
  (2022.0 +  6/12, 0, 2, 0,  0,  0),
  (2022.0 +  8/12, 0, 0, 1,  0,  0),
  (2022.0 + 10/12, 0, 1, 3,  1,  0),
  (2022.0 + 11/12, 0, 0,10,  0,  0),
  (2023.0 +  0/12, 0, 0, 2,  1,  0),
  (2023.0 +  1/12, 0, 0,10,  0,  0),
  (2023.0 +  2/12, 0, 0, 8,  9,  0),
  (2023.0 +  3/12, 0, 0,23,  8,  0),
  (2023.0 +  4/12, 0, 0, 6,  1,  6),
  (2023.0 +  5/12, 0, 0, 3,  3,  0),
  (2023.0 +  6/12, 0, 0, 3,  0,  0),
  (2023.0 +  8/12, 0, 0, 3,  2,  0),
  (2023.0 +  9/12, 0, 0, 6,  0,  0),
  (2023.0 + 10/12, 0, 1, 0,  2,  0),
  (2023.0 + 11/12, 0, 6, 4,  0,  0),
  (2024.0 +  0/12, 0, 6, 2,  1,  0),
  (2024.0 +  1/12, 0, 2, 1,  0,  0),
  (2024.0 +  2/12, 0, 0, 1,  0,  0),
  (2024.0 +  3/12, 0, 1, 0,  0,  5),
  (2024.0 +  5/12, 0, 3, 0,  4,  0),
  (2024.0 +  6/12, 0, 2, 0,  5,  0),
  (2024.0 +  7/12, 0, 1, 0,  0,  0),
  (2024.0 +  8/12, 0, 0, 1,  2,  0),
  (2024.0 +  9/12, 0, 1, 0,  1,  0),
  (2024.0 + 10/12, 0, 0, 1,  2,  0),
  (2024.0 + 11/12, 0, 3, 0,  2,  0),
  (2025.0 +  0/12, 0, 6, 0,  2,  0),
  (2025.0 +  1/12, 0, 1, 1,  0,  0),
  (2025.0 +  2/12, 0, 2, 0,  2,  0),
  (2025.0 +  3/12, 0, 1, 0,  0,  0),
  (2025.0 +  4/12, 0, 1, 0,  7,  0),
  (2025.0 +  6/12, 0, 0, 0,  2,  0),
  (2025.0 +  8/12, 0, 3, 0,  1,  0),
  (2025.0 +  9/12, 0, 0, 0,  3,  2),
  (2025.0 + 10/12, 0, 2, 0,  2,  0),
  (2025.0 + 11/12, 0,13, 0,  1, 11),
  (2026.0 +  0/12, 1, 5, 0,  2,  0),
  (2026.0 +  1/12, 0, 9, 0,  1,  0),
  (2026.0 +  2/12, 0, 1, 0,  0,  8),
  (2026.0 +  3/12, 0, 3, 0,  7,  0),
  (2026.0 +  4/12, 0, 2, 0,  0,  5),
)

// Build cumulative series: sorted by time, accumulate per vendor
#let vendors = ("Apple", "MediaTek", "Qualcomm", "Samsung", "Unisoc")
#let vi      = (0, 1, 2, 3, 4)  // column indices in monthly (offset by 1)

// Sort monthly by time
#let sorted = monthly.sorted(key: m => m.at(0))

// Compute cumulative totals → array of (t, ca, cm, cq, cs, cu)
#let series = {
  let cum = (0, 0, 0, 0, 0)
  let out = ()
  for m in sorted {
    let t = m.at(0)
    cum = cum.zip(vi.map(i => m.at(i + 1))).map(p => p.at(0) + p.at(1))
    out.push((t,) + cum)
  }
  out
}

// Chart dimensions (in pt, we'll work in a coordinate space)
#let W = 7.4cm
#let H = 5.8cm
#let pad-l = 1.1cm
#let pad-b = 0.7cm
#let pad-t = 0.15cm
#let pad-r = 0.2cm

#let plot-w = W - pad-l - pad-r
#let plot-h = H - pad-b - pad-t

#let t-min = 2010.0
#let t-max = 2026.5
#let y-max = 115  // slightly above Qualcomm's 108

#let tx(t) = pad-l + (t - t-min) / (t-max - t-min) * plot-w
#let ty(y) = pad-t + plot-h - y / y-max * plot-h

// Y-axis gridlines & labels
#let y-ticks = (0, 20, 40, 60, 80, 100)
// X-axis ticks (years with data)
#let x-ticks = (2010, 2012, 2014, 2016, 2018, 2020, 2022, 2024, 2026)

#lgd(vendors.map(v => (v, ven-c.at(v))), cols: 5)

#box(width: W, height: H, {
  // gridlines + y labels
  for yt in y-ticks {
    let y = ty(yt)
    // gridline
    place(dx: pad-l, dy: y,
      line(length: plot-w, stroke: rgb("#E0E0E0") + 0.4pt))
    // label
    place(dx: 0pt, dy: y - 3.5pt,
      box(width: pad-l - 3pt, align(right, tck(str(yt)))))
  }
  // x-axis ticks & labels
  for xt in x-ticks {
    let x = tx(float(xt))
    place(dx: x, dy: pad-t + plot-h,
      line(length: 3pt, angle: 90deg, stroke: rgb("#999") + 0.4pt))
    place(dx: x - 8pt, dy: pad-t + plot-h + 3pt,
      box(width: 16pt, align(center, tck(str(xt)))))
  }
  // axes
  place(dx: pad-l, dy: pad-t,
    line(start: (0pt, plot-h), end: (plot-w, plot-h), stroke: rgb("#555") + 0.5pt))
  place(dx: pad-l, dy: pad-t,
    line(start: (0pt, 0pt), end: (0pt, plot-h), stroke: rgb("#555") + 0.5pt))

  // draw lines per vendor
  for (vi2, vname) in vendors.enumerate() {
    let col = ven-c.at(vname)
    let pts = series.map(s => (tx(s.at(0)), ty(s.at(vi2 + 1))))
    // draw segments
    let i = 0
    while i < pts.len() - 1 {
      let (x0, y0) = pts.at(i)
      let (x1, y1) = pts.at(i + 1)
      place(dx: x0, dy: y0,
        line(start: (0pt, 0pt), end: (x1 - x0, y1 - y0),
             stroke: col + 1.2pt))
      i += 1
    }
    // end dot
    let (xf, yf) = pts.last()
    place(dx: xf - 2pt, dy: yf - 2pt,
      circle(radius: 2pt, fill: col, stroke: none))
  }
})

#cap(8, [Cumulative CVEs disclosed per vendor over time.])

The cumulative growth chart  reveals markedly different research trajectories.
Qualcomm accumulated slowly until 2021, then surged steeply through 2023 as modem fuzzing
infrastructure matured and Google's Pixel modem team published large advisory batches documenting
over-the-air attack surfaces on Snapdragon modems @pixel_pres @google_pixel_bulletin. Samsung and
MediaTek follow parallel growth curves from 2022: Samsung's acceleration is driven by focused Exynos
Layer-2 research @taszk_there_will_be_bugs, while MediaTek's is driven by TASZK Security
Labs campaigns uncovering IMS heap overflows @taszk_mtk_volte_725 @taszk_CVE-2025-20727 and GSM
stack vulnerabilities @taszk_hof, alongside regular bulletin releases @mediatek_psb_jan2026
@mediatek_psb_nov2025. Unisoc remained near zero until 2023 when systematic analysis of its baseband
began. Apple is sparsely represented at two CVEs across the entire corpus, largely because Apple
devices have historically relied on Qualcomm cellular modems; the company's first proprietary
baseband chip (the C1) was only released in 2025, prior to 2025 we included CVEs affecting Apple baseband which are not available on the Qualcomm's bulletins.

== Impact Distribution by Vendor

#lgd((("RCE",imp-c.RCE),("PrivEsc",imp-c.PrivEsc),("RCE/DoS",imp-c.at("RCE/DoS")),("DoS",imp-c.DoS)))

#let vi-data = (
  ("Apple",   (1,0,0,1)),
  ("MediaTek",(19,5,20,44)),
  ("Qualcomm",(5,0,29,74)),
  ("Samsung", (19,1,26,39)),
  ("Unisoc",  (1,0,5,31)),
)
#for (l, c) in vi-data {
  let (a,b,d,e) = c
  sbar(l, ((a,imp-c.RCE,"R"),(b,imp-c.PrivEsc,"P"),(d,imp-c.at("RCE/DoS"),"RD"),(e,imp-c.DoS,"D")))
}
#cap(5, [Proportional impact per vendor. Samsung and MediaTek share ~22% RCE rate.])

DoS-class bugs are the plurality or majority across all five vendors. Apple
carries the highest RCE fraction at 50%, though its sample of only two CVEs precludes statistical
inference @apple_ios_cve_2010_3832 @apple_ios_cve_2018_4148. MediaTek shows the most diverse impact
profile (22% RCE, 23% RCE/DoS, and 6% Privilege Escalation alongside 50% DoS) showing a broad research
surface spanning GSM heap overflows @taszk_hof, GPRS parsing bugs @taszk_pncd_2022, and IMS SIP
stack vulnerabilities @taszk_mtk_volte_678 @taszk_CVE-2025-20727. Qualcomm is skewed toward
lower-severity bugs with 69% DoS, though its 27% RCE/DoS fraction represents a substantial body of
exploitable memory corruption across NAS and Upper Layers (IP, DNS, TCP). Samsung records 19 confirmed
RCE CVEs (22%), consistent with focused Radio Layer-2 and IMS attack-surface research on Exynos
modems @taszk_there_will_be_bugs @samsung_cve_2023_26072 @samsung_cve_2023_26073. Unisoc shows only
3% RCE and 84% DoS, likely reflecting the nascent state of its security research coverage.

#colbreak()

== Impact Breakdown per Subsystem

#sec[D. Impact per Subsystem]

#lgd((("RCE",imp-c.RCE),("PrivEsc",imp-c.PrivEsc),("RCE/DoS",imp-c.at("RCE/DoS")),("DoS",imp-c.DoS)))

#let si-data = (
  ("2G",          (8,0,5,0)),
  ("4G/LTE",      (5,0,4,36)),
  ("5G/NR",       (5,0,3,19)),
  ("IMS",         (9,0,11,11)),
  ("SMS",         (1,0,2,2)),
  ("SIM",         (2,0,5,3)),
  ("Upper Levels",(0,0,11,25)),
  ("Local",       (0,6,13,12)),
  ("Multi-RAT",   (5,0,9,13)),
  ("Unknown",     (10,0,17,68)),
)
#for (l, c) in si-data {
  let (a,b,d,e) = c
  sbar(l, ((a,imp-c.RCE,"R"),(b,imp-c.PrivEsc,"P"),(d,imp-c.at("RCE/DoS"),"RD"),(e,imp-c.DoS,"D")))
}
#cap(4, [Proportional impact per subsystem. 2G shows highest RCE rate (62%).]) 
<fig:rat_impact>

The diagram highlights the unknown category (95 CVEs, 29.7%) and 4G/LTE (45 CVEs, 14.1%) as the two largest categories. A notable additional category is Multi-RAT at 27 CVEs (8.4%), covering bugs whose descriptions span or are ambiguous between multiple radio-access generations, within this group, 19% are confirmed RCE and 33% RCE/DoS, suggesting that cross-generation interworking code is a disproportionately dangerous attack surface.

Within 4G/LTE, DoS dominates at 80% (36 CVEs), with 9% RCE/DoS reflecting memory corruption in NAS
and RRC message parsers @samsung_cve_2023_26496 @samsung_cve_2023_26497 @samsung_cve_2023_26498 and
5 confirmed RCE entries (11%). The 5G/NR bar reaches 27 CVEs, predominantly DoS (70%, 19 CVEs) and 5 confirmed RCE entries (19%).

IMS (31 CVEs) carries the highest RCE proportion among the labelled subsystems at 29% (9 CVEs), as
SIP and SDP message parsing has been a productive attack surface since the early VoLTE era
@samsung_cve_2024_25073 @taszk_CVE-2025-20727. The 2G bar (13 CVEs) is the most dangerous by impact composition: 62% confirmed RCE (8 CVEs).

The SIM subsystem (10 CVEs, 50% RCE/DoS) warrants attention: the
SIMurai work @lisowski_usenix2024 demonstrated that a malicious or compromised SIM card can trigger
high-severity baseband bugs.\

Local (31 CVEs) is dominated by Privilege Escalation (19%) and RCE/DoS (42%),
consistent with IPC interface vulnerabilities that require local access but enable modem privilege
escalation. Upper Levels (36 CVEs) contains no confirmed RCE entries, all are RCE/DoS or DoS,
representing an underestimated attack surface, most of the baseband research being focused on cellular specific protocols, it is worth noting that these Upper layers bugs are mainly affecting Qualcomm chipsets though.\

The CVEs we could not assign to a specific component due to the lack of details in the description (95 CVEs, 72% DoS, 11% confirmed RCE, 18% RCE/DoS) show that
vendor advisories frequently omit protocol context even for potentially critical bugs.
#colbreak()
== Subsystem vs. Year Heatmap

// CVE Heatmap: Subsystem × Year — IEEE single-column fit (~8.3cm wide)

#let raw = (
  ("2G",2010,1),("2G",2020,1),("2G",2021,3),("2G",2022,2),("2G",2023,2),("2G",2024,3),("2G",2025,1),
  ("4G/LTE",2017,1),("4G/LTE",2021,1),("4G/LTE",2022,4),("4G/LTE",2023,18),("4G/LTE",2024,10),("4G/LTE",2025,7),("4G/LTE",2026,4),
  ("5G/NR",2023,14),("5G/NR",2024,3),("5G/NR",2025,7),("5G/NR",2026,3),
  ("IMS",2018,1),("IMS",2023,17),("IMS",2024,5),("IMS",2025,4),("IMS",2026,4),
  ("SMS",2020,1),("SMS",2023,2),("SMS",2026,2),
  ("SIM",2018,1),("SIM",2022,2),("SIM",2023,4),("SIM",2024,2),("SIM",2026,1),
  ("Upper Levels",2019,1),("Upper Levels",2020,1),("Upper Levels",2021,4),
  ("Upper Levels",2022,1),("Upper Levels",2023,28),("Upper Levels",2024,2),
  ("Local",2018,2),("Local",2019,3),("Local",2020,1),("Local",2021,6),
  ("Local",2022,1),("Local",2023,11),("Local",2024,6),("Local",2025,1),
  ("Multi-RAT",2019,1),("Multi-RAT",2020,1),("Multi-RAT",2021,4),("Multi-RAT",2022,3),
  ("Multi-RAT",2023,4),("Multi-RAT",2024,9),("Multi-RAT",2025,5),
  ("Unknown",2018,2),("Unknown",2020,2),("Unknown",2021,2),("Unknown",2022,7),
  ("Unknown",2023,7),("Unknown",2024,7),("Unknown",2025,38),("Unknown",2026,30),
)

#let subsystems = ("2G","4G/LTE","5G/NR","IMS","SMS","SIM","Upper Levels","Local","Multi-RAT","Unknown")
#let years      = (2010,2017,2018,2019,2020,2021,2022,2023,2024,2025,2026)

#let get(sub, yr) = {
  let r = 0
  for item in raw { if item.at(0)==sub and item.at(1)==yr { r = item.at(2) } }
  r
}

// Blend white → subsystem color by intensity (t in 0..1)
#let cell-bg(sub, c) = {
  if c == 0 { return rgb("#F5F5F5") }
  let base = sub-c.at(sub, default: rgb("#999999"))
  let t = calc.min(c / 38, 1.0)
  let white-pct = calc.round((1 - t) * 100, digits: 0)
  let color-pct = calc.round(t * 100, digits: 0)
  color.mix((white, white-pct * 1%), (base, color-pct * 1%))
}

#let cw  = 0.59cm
#let ch  = 0.45cm
#let lw  = 1.55cm
#let hbg = rgb("#37474F")

#lgd(subsystems.map(s => (s, sub-c.at(s, default: rgb("#999")))), cols: 4)

#grid(
  columns: (lw,) + years.map(_ => cw),
  rows: auto,
  gutter: 0pt,

  rect(width: lw, height: 0.28cm, fill: hbg, stroke: none)[],
  ..years.map(yr =>
    rect(width: cw, height: 0.28cm, fill: hbg, stroke: none, inset: 0.5pt)[
      #align(center + horizon)[
        #text(fill: white, size: 4.8pt, weight: "bold")[#str(yr)]
      ]
    ]
  ),

  ..subsystems.map(sub => (
    rect(width: lw, height: ch, fill: hbg, stroke: none,
         inset: (left: 3pt, right: 1pt, top: 0.5pt, bottom: 0.5pt))[
      #align(left + horizon)[
        #text(fill: white, size: 5.5pt, weight: "bold")[#sub]
      ]
    ],
    ..years.map(yr => {
      let c = get(sub, yr)
      rect(width: cw, height: ch, fill: cell-bg(sub, c),
           stroke: white + 0.5pt, inset: 0.5pt)[
        #align(center + horizon)[
          #if c > 0 {
            text(
              size: 5.5pt,
              weight: if c >= 5 { "bold" } else { "regular" },
              fill: if c >= 22 { white } else { rgb("#222") },
            )[#str(c)]
          }
        ]
      ]
    })
  )).flatten(),
)

#cap(7, [CVE counts per subsystem per year.])
<fig:heatmap>

The heatmap shows sparse coverage across all subsystems before 2021 followed by a
dense cluster in 2023, which alone accounts for 107 CVEs (33.4% of the entire corpus). The 4G/LTE row
peaks in 2023, driven by the batch of Samsung Exynos advisories and Layer 2 fuzzing research @taszk_there_will_be_bugs. IMS concentrates a large share of its 31 total CVEs
in 2023, reflecting an intense research focus on VoLTE and VoWiFi attack surfaces that
continued into 2024 and 2025 @taszk_CVE-2025-20727 @taszk_mtk_volte_678.
Upper Levels spikes sharply in 2023 then drops to near-zero, corresponding to a single concentrated
Qualcomm advisory cycle covering Upper-layer parsing bugs. Multi-RAT bugs, essentially absent before 2022,
track the growing complexity of dual-SIM and
NSA 5G device configurations as well as the shared use of NAS parsing code between 4G and 5G. 5G/NR grows steadily from 2022 through 2025, consistent with
expanding research coverage of NR-specific protocol layers @cracking_fortress @logic_gone. The unknown row grows from single digits before 2022 to its highest values in 2025 (38 CVEs that
year) and the first months of 2026 (30 CVEs), indicating that disclosure quality has not kept pace
with disclosure volume and is correlated to the growing reports from MediaTek and Unisoc with roughly 60% of their reported CVEs being classified as impacting an unknown component of the baseband.

== Vendor Specialisation Radar

#lgd(sub-c.pairs().map(p => (p.at(0), p.at(1))), cols: 4)

#let vs-data = (
  ("Apple",   (("2G",1),("Unknown",1))),
  ("MediaTek",(("2G",4),("4G/LTE",3),("5G/NR",7),("IMS",6),
               ("Upper Levels",4),("Local",5),("Multi-RAT",9),("Unknown",50))),
  ("Qualcomm",(("2G",2),("4G/LTE",14),("5G/NR",7),("IMS",6),("SMS",2),
               ("SIM",7),("Upper Levels",30),("Local",16),("Multi-RAT",6),("Unknown",18))),
  ("Samsung", (("2G",6),("4G/LTE",23),("5G/NR",13),("IMS",15),("SMS",3),
               ("SIM",3),("Upper Levels",2),("Local",4),("Multi-RAT",12),("Unknown",4))),
  ("Unisoc",  (("4G/LTE",5),("IMS",4),("Local",6),("Unknown",22))),
)
#for (v, subs) in vs-data {
  sbar(v, subs.map(s => (s.at(1), sub-c.at(s.at(0), default: rgb("#999")), s.at(0))))
}
#cap(6, [Subsystem composition per vendor.])

This chart normalises CVE counts per subsystem as a fraction of each vendor's
total, revealing research focus rather than raw volume. Samsung extends strongly toward 4G/LTE
(27% of its CVEs) and 5G/NR (15%), with a secondary extension toward IMS (18%), consistent with
Exynos-focused Layer-2, NAS, and VoLTE research @taszk_there_will_be_bugs @samsung_cve_2023_26496.
Qualcomm shows the broadest coverage, reaching into Upper Levels (28%) and Local components (15%), consistent
with the wide IPC and network-layer diagnostic interface attack surface available on Snapdragon
platforms. MediaTek shows 57% of its CVEs impacting an unknown component
suggesting that MediaTek advisories systematically omit protocol context. Unisoc shows
a similar skew toward Unknown (60%) and Local (16%) suggesting a similar behavior.
The relative absence of SMS, SIM, and explicit 2G contributions across most vendor profiles indicates
these subsystems are under-researched relative to their demonstrated attack-surface importance
@lisowski_usenix2024 @woot12_weinmann.



= Discussion

== The Unknown Category

The largest single subsystem bucket is Unknown at 95 CVEs, representing 29.7% of the corpus. These
are CVEs whose NVD description is either too generic or entirely absent of protocol context. Two
compounding factors explain this. Chipset vendors routinely omit the affected protocol layer
from public advisories @samsung_psu @mediatek_psb.  Reducing the Unknown fraction below 10% would require automated extraction from
patch diffs and heavy automated reversing efforts, or systematic manual annotation of recent advisories.

== Acceleration of Disclosure Volume

The inflection in 2022–2023 is attributable to several concurrent developments: the maturation of
open-source baseband emulation and fuzzing frameworks @firmwire_ndss2022 @samsung_cve_2024_20039
@overcoming_state @otabase; increased investment by red team teams focused on modem attack surface research
@pixel_pres; the novel SIM-as-attacker threat model that expanded fuzzing to non-OTA components
@lisowski_usenix2024; and the disclosure pressure following the Project Zero
Exynos batch @p0_exynos_2023 and the multiple research from Taszk Labs @taszk_mtk_volte_678 @taszk_CVE-2025-20727. The sustained but elevated post-2023 volume (47 CVEs in 2024 and 63
in 2025) suggests the field has not plateaued, though the growing Unknown fraction indicates that
advisory quality lags behind advisory quantity. The partial shift toward 5G/NR and Multi-RAT in
2024–2026 may reflect research effort moving toward 5G-specific areas not yet fully reflected in
confirmed-RCE disclosures @cracking_fortress @logic_gone.

== Limitations

Classification accuracy has not been formally evaluated against a ground-truth labelled dataset;
false negatives resulting in Unknown assignment are expected even though the results were checked manually. The
manual enrichment table covers a subset of the corpus, and biases from selective annotation may skew
subsystem and impact distributions. HiSilicon (Huawei) are entirely absent.

= Conclusion

The 320-CVE corpus analysed here shows that 4G/LTE (45 CVEs) and 5G/NR (27 CVEs) are the most heavily affected labelled baseband subsystems, that confirmed RCE and memory-corruption bugs appear in every vendor's portfolio with 2G being disproportionately dangerous (62% RCE) and Samsung carrying the highest RCE fractions among modern vendors, and that disclosure volume accelerated sharply in 2022–2023 driven by maturing emulation and fuzzing tooling @firmwire_ndss2022
@overcoming_state, the SIM-as-attacker threat model @lisowski_usenix2024, and concentrated vendor
advisory cycles @p0_exynos_2023 @taszk_there_will_be_bugs. Multi-RAT interworking code emerges as a disproportionately high-severity category (19% RCE, 33% RCE/DoS across 27 CVEs) that deserves dedicated research attention. Approximately 29.7% of CVEs cannot be assigned a specific protocol label from public descriptions alone, highlighting a systemic transparency gap in vendor advisories
@samsung_psu @mediatek_psb that limits the community's ability to prioritise defensive efforts.

// ─────────────────────────────────────────────────────────────────────────────
// APPENDICES
// ─────────────────────────────────────────────────────────────────────────────

= Appendix A: Data Collection Pipeline <appendix:scraping>

All CVE records were collected from OpenCVE (`app.opencve.io`) using a browser-impersonating HTTP
client. The same script was run once per vendor, with the search query parameterised by description
keyword and vendor name (e.g. `description:modem AND vendor:qualcomm`). Paginated search result
pages are fetched in sequence; from each page, CVE identifiers are extracted with a regular
expression and deduplicated across pages to produce a flat list of OpenCVE detail URLs for that
vendor.

Each detail URL is then fetched individually. OpenCVE embeds the raw NVD-format CVE JSON inside a
`modal-mitre-json` div on the page, rendered with decorative UI elements. The scraper strips
`rainbowType` spans and `rainbowToggle` anchors from that div and parses the remaining text as JSON,
recovering a standard CVE JSON 5.x record. From this record, the pipeline extracts the canonical CVE
identifier from `cveMetadata.cveId`, the English description from `containers.cna.descriptions`, the
publication timestamp from `cveMetadata.datePublished`, and CWE problem-type information from either
`containers.cna.problemTypes` or `containers.adp[0].problemTypes`, checking both locations because
vendor submission practice is inconsistent. CVSS metrics, affected version ranges, and reference URLs
are extracted by analogous field lookups with fallbacks to visible page elements when JSON fields are
absent.

The collected records for each vendor are written to a dedicated JSON file
(`cve_qualcomm_clean.json`, `cve_samsung_clean.json`, `cve_mediatek_clean.json`,
`cve_unisoc_clean.json`). Additionally to these raw scrapped data we added manually the descriptions of certain CVEs based on blogposts, papers and conferences to increase both the amount and the quality of the descriptions of the corpus. These four files plus manually fetched CVEs typst formatted results are the sole input to the classification and visualisation
pipeline.

= Appendix B: RAT and Subsystem Classification <appendix:rat>

Each CVE description is mapped to one or more of the ten subsystem labels shown in @tab:taxonomy based on the provided description and tests it
against a list of over 130 compiled regular expressions. Each pattern maps to a
four-element hierarchy tuple of domain, sublayer, component, and detail. The domain field determines
the chart label shown in the results section. Multi-label assignment is supported; a CVE matching
multiple domains is marked as Multi-RAT and comprises 27 CVEs (8.4%)
of the corpus.

#figure(
  table(
    columns: (auto, 3fr),
    stroke: 0.4pt,
    [*Label*], [*Description*],
    [2G],          [GSM/GERAN stack including RR, MM, GPRS, and OTASP],
    [3G],          [UMTS/WCDMA stack including call control and supplementary services],
    [4G/LTE],      [EPS stack: NAS (EMM/ESM), RRC, PDCP, RLC, MAC, and LwM2M],
    [5G/NR],       [NR stack: NAS (NRMM), RRC, MAC RAR, BWP, and NSA interworking],
    [IMS],         [IP Multimedia Subsystem: SIP, SDP, RTP/RTCP, RCS, IKEv2, VoLTE/VoWiFi],
    [SMS],         [Short Message Service: RP and TP layer parsing, WMS],
    [SIM],         [SIM/UICC: UIM, GSTK/USAT, APDU, PKCS\#15 file parsing],
    [Upper Levels],[Network-layer protocols: DNS, CoAP, PPP, IGMP, IPv4/IPv6, TLS/DTLS],
    [Local],       [Intra-device interfaces: CCCI/QMI/WMI IPC, DMA, EFS, SMMU, diagnostics],
    [Multi-RAT],   [CVEs whose description matches two or more top-level domain labels],
    [Unknown],     [Description insufficient to assign a subsystem label],
  ),
  caption: [RAT/subsystem taxonomy.],
) <tab:taxonomy>

A small set of CVE identifiers bypasses keyword matching entirely,
covering cases where the description is too generic or ambiguous. When the keyword matcher assigns
Unknown but the Typst annotation records a specific protocol, an enriched description is constructed
by prepending the Typst protocol string to the original text and the matcher is re-run. This
two-pass strategy resolves many ambiguous records without requiring per-CVE hard-coding.

= Appendix C: Impact Classification <appendix:impact>

Impact severity is assigned in the following priority order:

#figure(
  table(
    columns: (auto, 3fr),
    stroke: 0.4pt,
    [*Tier*], [*Matched CWE / Keywords*],
    [RCE],     [Explicit "remote/arbitrary code execution" language],
    [PrivEsc], ["Escalation of privilege", "privilege escalation", "elevation of privilege"],
    [RCE/DoS], [Memory-corruption primitives: OOB-write (CWE-787), buffer overflow
                (CWE-120/121/122), use-after-free (CWE-416), double-free (CWE-415),
                heap/stack overflow, arbitrary write],
    [DoS],     [OOB-read (CWE-125), null pointer dereference (CWE-476), assertion (CWE-617),
                infinite loop (CWE-835), resource exhaustion (CWE-400/770), information
                disclosure, improper authentication or access control],
  ),
  caption: [Impact classification tiers in decreasing severity order.],
) <tab:impact>

A hardcoded set of 43 CVE identifiers (`_RCE_CVE_IDS`) confirmed as pre-authentication RCE by
advisory language or public proof-of-concept overrides the pattern matcher @samsung_cve_2023_26072
@samsung_cve_2023_26073 @taszk_hof @taszk_pncd_2022. A second set corrects
CVEs incorrectly promoted by the matcher and manually validated as a false positive. An additional upgrade pass (`_upgrade_impact`) demotes
RCE/DoS-classified CVEs to DoS when the Typst impact annotation indicates a purely denial-of-service
outcome, preventing over-classification from boilerplate memory-corruption CWE tags.
