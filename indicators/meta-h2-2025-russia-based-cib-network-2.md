# Indicators of Compromise: Russia-Based Influence Operation Network Targeting Sub-Saharan Africa

Meta disrupted a Russia-based Coordinated Inauthentic Behavior (CIB) network targeting Sub-Saharan Africa. This file contains Indicators of Compromise (IOCs) from Meta’s Adversarial Threat Report H2 2025.

## Meta’s Adversarial Threat Report Network Summary

### Proliferation of Local, For-Hire Influence In Sub-Saharan Africa 
Influence operation threat actors continue to adapt in response to our detection and enforcement efforts. In recent months, we’ve observed increasing use of freelance social media managers to execute influence operations in Africa on behalf of nation-state actors. Unlike commercial firms offering “IO-for-hire” services that we [reported](https://about.fb.com/wp-content/uploads/2021/05/IO-Threat-Report-May-20-2021.pdf) on in the past, these freelancers are often social media managers based in the same locale as the target audience. They use their authentic accounts to run social media for brands and promote content, and we believe they are unwitting of the true nature and sponsorship of the campaigns they are running.

Over the last six months, we have uncovered two campaigns targeting Africa in which local, for-hire individuals conduct influence activities on our platforms, likely on behalf of Russia-based actors. While we have previously [documented](https://about.fb.com/news/2019/10/removing-more-coordinated-inauthentic-behavior-from-russia/) Russia’s use of local cutouts in Africa as early as 2019, recent investigations reflect a proliferation of this tactic and a decreasing reliance by Russian networks to use strictly fake accounts. This evolution is a departure from typical influence operation models, where campaigns are run directly by commercial firms or nation-state actors through networks of inauthentic personas.

In most cases, we have no evidence to suggest that the for-hire individuals involved in these operations were aware of the ultimate Russian backing. Despite this, their activities - particularly their attempts to circumvent political ad detection and use of  fake accounts to continue operating their campaign after initial enforcements - violate Meta’s Coordinated Inauthentic Behavior policy and resulted in their removal from our platforms. 

Beyond perceived anonymity, leveraging local, for-hire individuals enables threat actors to minimize their online footprint and outsource phases of the online operations kill chain that are most vulnerable to platform detection, such as acquiring and disguising assets. By hiring locals that specialize in digital media management, influence actors effectively obtain local infrastructure, mature and authentic social media accounts, and target-specific knowledge, all of which facilitate the operation’s ability to integrate smoothly into the local information environment. This tactic also facilitates longevity - another phase in the online operations kill chain -  as we’ve observed threat actors quickly replace social media managers when previous ones are removed, allowing campaigns to continue with minimal downtime. 

As platforms continue to improve detection of inauthentic behavior, we assess that influence actors could increase their use of paid intermediaries for influence operations. This report aims to increase awareness of this issue, enabling digital freelancers to critically evaluate who they’re working for and thereby help them avoid disruptions to their legitimate income streams. The following sections provide details on two recent investigations that use this tactic.

### Case Study 1: Freelancers Drive Coordinated Political Influence
We removed 67 Facebook accounts, 70 Pages, and 2 Groups for violating our policy against Coordinated Inauthentic Behavior. About 621,400 accounts followed one or more of these Pages, and about 4,200 accounts followed one or more of these Groups. The network engaged in around $107,300 in spending for ads on Facebook and Instagram, paid for mostly in US dollars, South African Rands, and Nigerian Nairas. This network targeted multiple countries throughout sub-Saharan Africa and leveraged local freelancers, likely working on behalf of individuals in Russia. The operation created Pages purporting to be local and original media outlets and ran ads that denigrated African partnerships with France and the United States and promoted Russian geopolitical interests.

A decentralized network of individuals, claiming to be social media managers, drove this operation across primarily Mali, Burkina Faso, Gabon, Nigeria, South Africa, Senegal, Angola, and Benin. These individuals, some of which maintained active profiles on freelance platforms like Upwork, stated they were social media managers or search engine optimization specialists, for example. 

On our platform, these individuals created Facebook Pages that masqueraded as local media or news outlets and ran undeclared political ads that typically targeted multiple African countries. The individuals behind these Pages repeatedly returned to our platform after we removed them, often using fake accounts to recreate similar brands. This network of individuals operated independently, though they likely received centralized tasking through channels outside of Meta’s platform. This assessment is supported by our observations of these individuals running the same or slightly adjusted ad content - often within a two day window - and utilizing the same text obfuscation methods, such as “4ng0la, “uk_ra_ine”, and “fr@nce”.

To a lesser extent, the operation leveraged established, authentic media outlets on Facebook that offered paid advertisements, typically including “DM for ads” or similar language in their Page descriptions. These advertisements featured similar political themes, text obfuscation methods, and coordination indicators as the broader network.

We found this network as a result of our internal investigation into suspected coordinated inauthentic behavior in the region. Our analysis benefited from [reporting](https://www.sgdsn.gouv.fr/files/2025-02/20250224_TLP-CLEAR_NP_SGDSN_VIGINUM_War%20in%20Ukraine_Three%20years%20of%20Russian%20information%20operations_1.0_VF.pdf) produced by France’s Vigilance and Protection Service against Foreign Digital Interference (VIGINUM).

### Case Study 2: RT-Linked Covert Campaign Operated by Africa-Based Individuals
We removed 10 Facebook accounts, 2 Pages, and 9 Instagram accounts for violating our policy against Coordinated Inauthentic Behavior. About 20,800 accounts followed one or more of these Pages, and about 3,100 accounts followed one or more of these Instagram accounts. This network targeted numerous sub-Saharan African countries and leveraged a Cameroon-based freelancer, likely working on behalf of employees of RT, a Russian state-controlled media entity. 

The individuals behind this activity attempted to create two seemingly independent, grassroots media outlets, establishing a presence across multiple internet platforms including Telegram, TikTok, Facebook, Instagram, and X. On our platform, the brands - Allô Afrique and Derniere Minute - posted in French and targeted audiences with international news, seeding narratives on Russia’s stance on Ukraine and the West, and at times, shared RT-branded content. These brands also posted videos periodically featuring RT employees without acknowledging their affiliation to the Russian-controlled media outlet.

For the majority of time this campaign ran, a Cameroon-based individual operated the Facebook and Instagram accounts associated with these brands. This individual was associated with a Page advertising the individual’s own digital communications agency. We assess it is possible the operator had knowledge of the ultimate sponsor of this operation.

We found this activity as a result of an internal investigation into suspected coordinated inauthentic behavior in the region and identified links to a past influence operation we removed and reported in [November 2023](https://scontent-iad3-2.xx.fbcdn.net/v/t39.8562-6/406961197_3573768156197610_1503341237955279091_n.pdf?_nc_cat=105&ccb=1-7&_nc_sid=b8d81d&_nc_ohc=w6Sj5z4AE64Q7kNvwHqHILK&_nc_oc=Adk-MTyFAGS2fk6MiEJFFunlUKOJ4frhdtt5pw2r2yGmEGgT-WEF7P9YHqFgjZBuR2k&_nc_zt=14&_nc_ht=scontent-iad3-2.xx&_nc_gid=iVjkfI5-OGmVlH9jWOal1A&oh=00_Afkzz6MYSAE1NjTwFX2U3aQ99WerEMxQ8Jfohd-OskPLbw&oe=693D0A92).

## Indicators of Compromise

*Note: URLs have been defanged for safety. Replace `[.]` with `.` to resolve.*

| Indicator Type | Indicator Value |
| :--- | :--- |
| Social Media Account | `hxxps://x[.]com/Allo_Afrique` |
| Social Media Account | `hxxps://x[.]com/dernierminute24` |
| Social Media Account | `hxxps://t[.]me/AlloAfrique` |
| Social Media Account | `hxxps://t[.]me/derniere_minute` |
| Social Media Account | `hxxps://www[.]youtube[.]com/@All%C3%B4Afrique` |

## Cross-Links

- **Full ATR Report:** [Meta Adversarial Threat Report H2 2025](https://transparency.meta.com/sr/Q2-Q3-2025-Adversarial-threat-report/)
- **AlienVault OTX Pulse:** [meta-h2-2025-russia-based-cib-network-2 on OTX](https://otx.alienvault.com/pulse/meta-h2-2025-russia-based-cib-network-2)
- **IOC File (GitHub):** [meta-h2-2025-russia-based-cib-network-2 on GitHub](https://github.com/facebook/threat-research/blob/main/indicators/meta-h2-2025-russia-based-cib-network-2.md)
