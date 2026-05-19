# Indicators of Compromise: Iran-Based Influence Operation Network Targeting United States, France, Israel, United Kingdom

Meta disrupted a Iran-based Coordinated Inauthentic Behavior (CIB) network targeting United States, France, Israel, United Kingdom. This file contains Indicators of Compromise (IOCs) from Meta’s Adversarial Threat Report H2 2025.

## Meta’s Adversarial Threat Report Network Summary

Iranian threat actors continue to violate Meta’s Coordinated Inauthentic Behavior policy, trailing only behind Russia for the most disruptions since we began threat reporting in 2017. As part of our regular updates on this activity, today we are sharing key insights and attribution updates for a long-running campaign known in the industry as Endless Mayfly. This set of linked networks spans from our first Iranian CIB disruption in 2018 through off-platform activity targeting the 2024 US elections.  

Our investigation has compiled multiple, corroborating lines of evidence from both internal investigations and public sources that attribute this multi-year operation to Iran’s International Union of Virtual Media (IUVM), a sanctioned propaganda group with close links to the Iranian government. This report sheds light on their persistent attempts to covertly run influence campaigns over the last decade. We hope this information contributes to the public understanding of this threat and provides the security community with context and data to anticipate, identify and respond to future campaigns.

### Overview & TTPs
In 2018, we [announced](https://www.google.com/url?q=https://about.fb.com/news/2018/08/more-coordinated-inauthentic-behavior/&sa=D&source=docs&ust=1765225866522669&usg=AOvVaw243ShHeCmDLerQaV5YkUFb) our first Iranian CIB takedown of the Liberty Front Press (LFP) network. This activity began in 2013, with operators primarily posing as news and civil society organizations. Over the last seven years we have continued to track, investigate, and disrupt operations evolving from this initial set, identified as “Endless Mayfly” by CitizenLab. We are able to link numerous networks together through both technical and behavioral indicators.
The operation’s content aligns with Iran’s foreign policy objectives and they consistently run campaigns targeting the US, France, Israel, UK and Iran’s regional interests. This network’s TTPs have evolved over the years, but certain hallmarks are notable throughout.
First, they operate domains on which they place misleading articles in an attempt to deceive users, directing traffic to them from social media channels. Often, these domains cross-amplify their content and frequently appear in Iranian state-owned media outlets. In earlier days, these domains often typosquatted popular news websites, but later evolved to bespoke, independent outlets covering issues of interest to the target demographics. 

Second, the threat actors often impersonate journalists or masquerade as students, creating social media personas to match corresponding bylines on their website articles. We have often observed them contacting authentic outlets and journalists in attempts to launder their narratives into mainstream press, even recycling personas across campaigns years apart. However, these efforts have been largely unsuccessful.

Third, the actors use consistent infrastructure and unique technical TTPs. This campaign demonstrated consistent, long-term reliance on a small Iranian hosting provider, and a limited range of primary IP addresses. In an apparent effort to obscure previously identified infrastructure, many websites within this network simultaneously moved from a long-used set of hosting IPs to a new set in early 2024. This coordinated migration inadvertently highlighted the interconnected nature of these assets. Since then, we have noted a continued diversification of hosts, likely in further attempts to avoid tracking. See our [Github repository](https://threatresearch-team.github.io/) for more detailed information.

Additionally, operators employed consistent elements in their recent WordPress-powered domains to include recycled analytics tags, common plugins, and consistent footer formats.

Public searches revealed this pattern to be exceedingly rare, and it surfaced an Iranian web designer who was the operator of a core cluster in the original LFP disruption nearly ten years prior. Consistent signatures demonstrated the full scope of the operation over the years, confidently linking subsequent campaigns. The technical connection of this original LFP operator to websites targeting the 2024 US election further reinforced our findings.

### Takeaways & Efficacy
Our ongoing detection and enforcement efforts against this network are working. Constant pressure by the collective security community has forced IUVM to burn useful personas, and slow their pace of operations by forcing them to reconstitute on new infrastructure. Our defenses have successfully reduced the traction these operations gain on our services, with recent campaigns abandoning our platforms altogether. By disrupting their personas, domains, and amplification networks, we diminish their ability to build organic audiences and scale widespread impact.
 
We are publishing this update and data in hopes that new information will contribute to the community’s ongoing understanding and defenses against these covert influence operations. Their track record demonstrates that IUVM is likely to continue to evolve their tactics in an attempt to evade detection and deceive audiences. This underscores the critical need for the entire defender community—including researchers, industry, and government agencies—to continue collaborating. By working together to detect, analyze, and publicly expose these evolving tactics, we can collectively increase the consequences for these malicious actors and ensure their harmful effects are minimized.

## Indicators of Compromise

*Note: URLs have been defanged for safety. Replace `[.]` with `.` to resolve.*

| Indicator Type | Indicator Value |
| :--- | :--- |
| Proxy IP | `45[.]141[.]152[.]19` |
| Proxy IP | `146[.]70[.]118[.]226` |
| Proxy IP | `45[.]141[.]152[.]18` |
| Proxy IP | `45[.]141[.]152[.]194` |
| Proxy IP | `5[.]9[.]29[.]230` |
| Proxy IP | `104[.]237[.]255[.]202` |
| Proxy IP | `116[.]202[.]235[.]13` |

## Cross-Links

- **Full ATR Report:** [Meta Adversarial Threat Report H2 2025](TBD)
- **AlienVault OTX Pulse:** [meta-h2-2025-iran-based-cib-network on OTX](https://otx.alienvault.com/pulse/meta-h2-2025-iran-based-cib-network)
- **IOC File (GitHub):** [meta-h2-2025-iran-based-cib-network on GitHub](https://github.com/facebook/threat-research/blob/main/indicators/meta-h2-2025-iran-based-cib-network.md)
