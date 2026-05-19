# Indicators of Compromise: Pakistan-Based Influence Operation Network Targeting Pakistan

Meta disrupted a Pakistan-based Coordinated Inauthentic Behavior (CIB) network targeting Pakistan. This file contains Indicators of Compromise (IOCs) from Meta’s Adversarial Threat Report H1 2026.

## Meta’s Adversarial Threat Report Network Summary

Under our CIB policy, we took down a network attributed to the Pakistani military’s Inter-Services Public Relations (ISPR) wing, which we observed using novel tactics and generative AI to target domestic audiences with nationalist narratives promoting Pakistan’s central government. Inauthentic networks manipulating public discourse are subject to enforcement regardless of their target audience, and the CIB policy applies equally to both domestic and foreign influence operations. Pakistan attempts influence operations on multiple fronts: state-linked actors aim to consolidate internal support while also conducting adversarial campaigns against regional rivals, as in the case of one we previously [reported in April of 2019](https://about.fb.com/news/2019/04/cib-and-spam-from-india-pakistan/). 

This case study highlights both a domestic influence operation, as well as the operation’s novel use of generative AI tools. While threat actors have previously experimented with AI, this operation moved beyond simple text generation or GAN-generated profile pictures; operators leveraged multiple AI tools to research targets, craft sophisticated, multimedia content, and custom personas designed to evade detection and increase engagement.

As part of this network, we actioned 23 Facebook accounts, 8 Pages, and 14 Instagram accounts for violating our policy against Coordinated Inauthentic Behavior. About 64,000 accounts followed one or more of these Pages, and about 5,000 accounts followed one or more of these Instagram accounts. The network also engaged in around $3,000 in spending for ads on Facebook and Instagram, paid for mostly in Pakistani Rupees. Our investigation into this activity began after we reviewed information shared by an industry peer. 

Our investigation uncovered the central use of fake accounts, which the network used to manage its assets and distribute content. The individuals behind this activity invested significantly in developing "custom personas" tailored to their target audience. These accounts posed as fictitious individuals, journalists, and activists from Balochistan, utilizing stolen profile pictures of people in regional garb with Balochi names, who posted flattering commentary about Balochi culture, and shared imagery such as Balochi flags to embellish their inauthentic identities. These inauthentic accounts were used to administer Pages, place ads, and amplify content to give the operation the appearance of a grassroots movement of local citizens, as opposed to a military influence campaign. 

The network’s primary objective was to promote Pakistani national sentiment. The operation anchored its narratives around established media brands created by the network, most notably a series of assets under the umbrella of a blog called "The Balochistan Diaries,” which boasted a multi-platform presence. To obscure the link between these assets and the ISPR, the network utilized a multi-layered distribution strategy, driving traffic to a standalone website, and maintaining a presence on other platforms such as X (formerly Twitter) and YouTube. To that end, this operation aimed to promote the central government, and spread nationalist messages of unity. 

This network represents a notable volume and range of AI use for influence operations. In no particular order, operators leveraged:
- AI tooling in order to identify potential targets of their operation;
- LLMs to generate polished prose in multiple languages, including English and Urdu, for the their network’s pages, websites, posts, and comments; 
- AI video generation to create photorealistic "journalist" personas, which were featured in video interviews posted to the network's Pages, adding a veneer of professional reporting to the operation that might otherwise have required significant resources to produce;
- Used AI tools to develop and promote the website, thebalchistandiaries[.]com, which hosted writing that was likely AI-assisted. Text in posts sharing links to the website on Facebook and Instagram was also likely AI-generated. Users in this network appeared to share AI-generated comments on posts from entities both within and outside the network, praising Pakistan’s government and criticizing its regional rivals in clean, consistent prose.

## Indicators of Compromise

*Note: URLs have been defanged for safety. Replace `[.]` with `.` to resolve.*

| Indicator Type | Indicator Value |
| :--- | :--- |
| Domain | `thebalochistandiaries[.]com` |
| Social Media Account | `https://x[.]com/auroraapricus/` |
| Social Media Account | `https://x[.]com/BalochDiaries` |
| Social Media Account | `https://x[.]com/shaziia_tweets` |
| Social Media Account | `https://x[.]com/Abbasbugti52` |
| Social Media Account | `https://www.youtube[.]com/@Baloch5225` |
| Social Media Account | `https://www.youtube[.]com/channel/UCQ8TUByC9EmbhoUDaInIGeA` |

## Cross-Links

- **Full ATR Report:** [Meta Adversarial Threat Report H1 2026](TBD)
- **AlienVault OTX Pulse:** [meta-h1-2026-pakistan-based-cib-network on OTX](https://otx.alienvault.com/pulse/meta-h1-2026-pakistan-based-cib-network)
- **IOC File (GitHub):** [meta-h1-2026-pakistan-based-cib-network on GitHub](https://github.com/facebook/threat-research/blob/main/indicators/meta-h1-2026-pakistan-based-cib-network.md)
