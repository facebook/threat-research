# Russia-Based Influence Operation Targeting Western audiences

Meta disrupted a Russia-based Coordinated Inauthentic Behavior (CIB) network targeting Western audiences. This file contains indicators of compromise and a network summary from Meta’s Adversarial Threat Report H2 2026.

## Meta’s Adversarial Threat Report Network Summary

We disrupted a Coordinated Inauthentic Behavior network originating in Russia and targeting Western audiences, with France as a primary focus. The operation maintained a cross-platform presence including on Telegram, TikTok, YouTube and X (threat indicators can be found in our [GitHub repository](https://threatresearch-team.github.io/)). We removed 7 Facebook accounts, 9 Pages, and 8 Instagram accounts for violating our policy against Coordinated Inauthentic Behavior. About 200 accounts followed one or more of these Pages and about 200 accounts followed one or more of these Instagram accounts. We determined through these enforcement actions that network operators engaged in around $6,400 in spending for ads on Facebook and Instagram, paid for mostly in US Dollars, Euros, and Guatemalan Quetzales. Meta’s investigation revealed links to actors in Russia.

The operation's central tactic was the creation and backstopping of a fabricated think tank called the "International Burke Institute," which posed as a legitimate academic institution based in Israel. Operators created a pseudo-scientific "Burke Sovereignty Index" that claimed it could measure the real independence of states. The index was invoked to support the operation’s narrative that certain countries were losing sovereignty to the US and institutions such as NATO and EU. The network used AI to create fake personas on Instagram—posing as analysts, investigative journalists, and former government employees—complete with AI-generated profile photos and face-to-camera video Reels of the same nonexistent individuals. The individuals behind this network attacked Western institutions within the United States and European governments, while portraying the latter as lacking true sovereignty. Furthermore, the operators attempted to launder their narratives into the legitimate academic realm by seeding fabricated research papers featuring fictitious authors into authentic academic research hosting platforms. We found this network after reviewing information shared with us by our peers at OpenAI.

## Indicators of Compromise

*Note: URLs have been defanged for safety. Replace `[.]` with `.` to resolve.*

| Indicator Type | Indicator Value |
| :--- | :--- |
| Domain | `ibi[.]institute` |
| Social Media Account | `http://x[.]com/institute_ibi` |
| Social Media Account | `burkeinstitute[.]substack[.]com` |
| Social Media Account | `http://t[.]me/institute_ibi` |
| Social Media Account | `http://tiktok[.]com/@camille_lefevre_fr` |
| Social Media Account | `http://tiktok[.]com/@etienne_lacroix` |
| Social Media Account | `http://tiktok[.]com/@laurentbergier` |
| Social Media Account | `http://tiktok[.]com/@luca_marcel` |
| Social Media Account | `http://tiktok[.]com/@marc_renier` |
| Social Media Account | `http://tiktok[.]com/@romain_garnier2` |
| Social Media Account | `http://tiktok[.]com/@sophierenoir0` |
| Social Media Account | `http://youtube[.]com/@Etienne_Lacroix` |
| Social Media Account | `http://youtube[.]com/@LaurentBergier` |
| Social Media Account | `http://youtube[.]com/@Le_Dernier_Mot` |
| Social Media Account | `http://youtube[.]com/@Le_Radar_Public` |
| Social Media Account | `http://youtube[.]com/@Marc-Rénier` |
| Social Media Account | `http://youtube[.]com/@SophieRenards1` |
| Social Media Account | `http://youtube[.]com/@camille_lefevre_fr` |
| Social Media Account | `http://youtube[.]com/@rRomainGarnier` |
| Social Media Account | `http://youtube[.]com/@ligne_Rougee` |

## Cross-Links

- **Full ATR Report:** [Meta Adversarial Threat Report H2 2026](TBD)
- **AlienVault OTX Pulse:** [h2-2026-russia-cib-based-network-2 on OTX](https://otx.alienvault.com/pulse/h2-2026-russia-cib-based-network-2)
- **IOC File (GitHub):** [h2-2026-russia-cib-based-network-2 on GitHub](https://github.com/facebook/threat-research/blob/main/indicators/h2-2026-russia-cib-based-network-2.md)
