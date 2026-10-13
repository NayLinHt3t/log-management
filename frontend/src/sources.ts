// Fixed order = fixed colour slot. The order was checked with a colour-vision-deficiency
// validator for adjacent pairs (the stacking order in the timeline). Colour follows the
// source, so filtering never repaints the remaining series.
export const SOURCES = ["firewall", "network", "api", "crowdstrike", "aws", "m365", "ad"] as const;
export type SourceId = (typeof SOURCES)[number];

export const SOURCE_LABEL: Record<string, string> = {
  firewall: "Firewall",
  network: "Network",
  api: "HTTP API",
  crowdstrike: "CrowdStrike",
  aws: "AWS",
  m365: "Microsoft 365",
  ad: "AD / Windows",
};

export const sourceColor = (s: string) => `var(--src-${s}, var(--bar-neutral))`;
export const sourceLabel = (s: string) => SOURCE_LABEL[s] ?? s;
export const sortSources = (list: string[]) =>
  [...list].sort((a, b) => {
    const ia = SOURCES.indexOf(a as SourceId);
    const ib = SOURCES.indexOf(b as SourceId);
    return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
  });
