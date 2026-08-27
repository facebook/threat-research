# Deep Dive: Beyond Brute Force—Doppelganger’s Changing Operations

Meta disrupted a Russia-based Coordinated Inauthentic Behavior (CIB) network targeting France, Germany, Hungary. This file contains indicators of compromise and a network summary from Meta’s Adversarial Threat Report H2 2026.

## Meta’s Adversarial Threat Report Network Summary

We continue to detect and enforce on Russia’s most persistent covert influence campaign, Doppelganger, which we first reported in 2022. Earlier this year, we observed a sudden cessation in Doppelganger activity on our platforms. A month later, Doppelganger returned to our services using the same brute-force tactics characteristic of this operation since late 2024. However, the actors primarily associated with Doppelganger—including ANO Dialog and Social Design Agency (SDA)—sustained these brute-force tactics while simultaneously standing up a number of tactically distinct offshoot campaigns. These campaigns feature more fluid targeting and a more diverse array of creatives than the original Doppelganger network. Throughout, we have continued to refine our automated detection based on the behaviors we observe and to engineer campaign-specific defenses to help block these operators from returning to our platforms. In the sections below, we break down various operations under the Doppelganger umbrella that we’ve observed since our last update.

### Brute Force Tactics Fluctuate But Persist

By late 2024, Doppelganger appeared on our platforms as a high-volume, low-quality operation that prioritizes sheer output over persona building. It runs ads with minimal text overlaid on images with no links to off-platform websites, builds no audience, and primarily targets Germany, France, and Israel. Utilizing a "brute force" approach across the internet, the network relies on a vast, constantly regenerating infrastructure of spoofed websites and attempts to seed its content across as many social media platforms and services as possible. Technically sophisticated adversaries, such as Doppelganger, employ advanced operational tradecraft and inauthentic accounts to evade detection by our automated systems and obfuscate their identities. However, as we have previously reported, Doppelganger’s attempts to run ads are quickly detected and blocked by our automated systems, typically before anyone sees them.

However, in late January 2026, the campaign's daily activity suddenly ceased for more than a month. The operation re-emerged in March with the same tactics, but this time targeting a new country, Hungary, ahead of its election. The narratives shared by the new offshoot were critical of EU-Hungary relations, linked Peter Magyar to George Soros, and suggested the Tisza party would undermine Hungarian interests through shadowy deals with Brussels. Our proactive defenses detected this new, Hungary-targeting activity before the election and we removed the violating assets from our platforms.  After this effort, in late May, the operation resumed its typical targeting of audiences in France and Germany, but notably dropped Israel from its targeting. 

###  Social Design Agency-Linked Offshoot Campaigns

Following the changes to Doppelganger's traditional operating mode, we observed several campaigns linked to the Social Design Agency (SDA), a Russian IT and public relations company to whom we publicly attributed to Doppelganger in 2022. In this reporting period, we removed multiple clusters of inauthentic activity linked to SDA actors under our protocols to enforce on CIB recidivism.  

An example of an SDA campaign we removed was a network of 10 Facebook accounts, 7 Pages, and 4 Instagram accounts targeting the EU and Ukraine, which we removed for violating our policy against coordinated inauthentic behavior.  About 1,300 accounts followed one or more of these Pages. The operators created fake accounts to amplify content from news brands—“Pulse NWS Media”, “Pulse Media UA”, for example—and actor-controlled domains eu-hot-news[.]com and ua-hot-news[.]com, that branded themselves as local media outlets while under the control of Russian actors. Advertisements directing audiences to these domains used hallmarks of earlier Doppelganger efforts, such as complex redirects—in this instance, using newspace[.]today—and geofencing, tactics we observed and reported on in 2023 and 2024. The operation distributed tailored narratives focused on Ukraine war fatigue, the rising cost of living, and delegitimizing President Zelenskyy. 

### ANO Dialog’s Growing Role

We have observed the Autonomous Non-Profit Organization (ANO) “Dialog” take a more active role in foreign-targeted covert influence campaigns. ANO Dialog is a state-linked organization founded in 2019 by the Moscow city government. The organization has previously been linked to the Doppelganger campaign by the U.S. Department of Justice, which attributed early Doppelganger infrastructure to ANO Dialog alongside the Social Design Agency (SDA) and Structura National Technology. We have also identified operational overlaps—most notably, both the Doppelganger campaign and a recent ANO Dialog network have outsourced work to the same contractor. We also observed tactical similarities, such as the common use of URL redirect techniques.

Below, we provide summaries of two covert influence campaigns we have attributed to ANO Dialog: 

We removed 25 Facebook accounts, 13 Pages, and 13 Instagram accounts for violating our policy against coordinated inauthentic behavior. About 9,600 accounts followed one or more of these Pages and about 10,400 accounts followed one or more of these Instagram accounts. The network targeted the June 2026 Armenian parliamentary elections attempting to boost the "Strong Armenia" party and Russian-Armenian billionaire Samvel Karapetyan. Apart from promoting their page in Armenia directly, this network also targeted the Armenian diaspora in Germany, France, and the US. To lend credibility to their operation, networks linked to this campaign repeatedly boosted authentic news articles aligned with their strategic objectives. To disseminate its messaging, the operation maintained a cross-platform presence, operating on our platforms as well as on TikTok and YouTube. Furthermore, the network redirected users to authentic media articles to lend credibility to its assets, and created distinct local media brands such as “Ar Media” to distribute its content.

We removed 69 Facebook accounts, 58 Pages, 3 Groups, and 14 Instagram accounts targeting Moldova, the US, Ukraine, and several African nations. About 8,000 accounts followed one or more of these Pages and about 900 accounts followed one or more of these Instagram accounts. Coordinated by ANO Dialog alongside the Russian PR firm ООО «ЮС-МЕДИА» (us-media[.]ru), this campaign closely integrated public opinion polling and classic influence campaigns. The surveys often used emotionally charged, leading questions to manipulate sentiment, and the resulting "data" was then disseminated via ads to make their narratives appear as trustworthy statistics. The fictitious “vocepentru / rvm” research institute, which was used to disguise public opinion surveys targeting Moldova, was first highlighted in a report by GLOBSEC, a global think tank headquartered in Slovakia.  The campaign also boosted authentic news articles to advance its goals; in the US, the network seeded positive coverage of Russian presidential representative Kirill Dmitriev into financially motivated "pay-to-play" news sites and promoted authentic Reuters and Politico articles about him. The operation at the same time distributed surveys to measure whether Americans viewed Dmitriev positively. 

### Countering Doppelganger’s Evolving Threat

We have remained vigilant through Doppelganger’s evolution from a single, centralized operation into a series of smaller, distinct campaigns over the last year. Our team is improving automated detection methods based on behaviors we observe and engineering campaign-specific defenses to block operators from returning to our platforms. This steady defensive pressure forces operators to evolve constantly, which degrades the quality of their campaigns and reduces the reach and impact of influence operations on our platforms and the broader internet.

## Indicators of Compromise

*Note: URLs have been defanged for safety. Replace `[.]` with `.` to resolve.*

| Indicator Type | Indicator Value |
| :--- | :--- |
| Domain | `armeniaopinion[.]com` |
| Domain | `news-md[.]com` |
| Domain | `newscong[.]life` |
| Domain | `opinion-world[.]com` |
| Domain | `vocea-mea[.]online` |
| Domain | `vocepentru[.]com` |
| Social Media Account | `http://tiktok[.]com/@garrygarr950` |
| Social Media Account | `http://youtube[.]com/@Newscong_life` |
| Social Media Account | `http://youtube[.]com/@Strong_Armenia_Team` |
| Social Media Account | `http://tiktok[.]com/@merdzevovteam` |
| Social Media Account | `http://tiktok[.]com/@strong_armenia_team` |
| Domain | `eu-hot-news[.]com` |
| Domain | `ua-hot-news[.]com` |
| Domain | `newspace[.]today` |

## Cross-Links

- **Full ATR Report:** [Meta Adversarial Threat Report H2 2026](TBD)
- **AlienVault OTX Pulse:** [h2-2026-russia-cib-based-network-4 on OTX](https://otx.alienvault.com/pulse/h2-2026-russia-cib-based-network-4)
- **IOC File (GitHub):** [h2-2026-russia-cib-based-network-4 on GitHub](https://github.com/facebook/threat-research/blob/main/indicators/h2-2026-russia-cib-based-network-4.md)
