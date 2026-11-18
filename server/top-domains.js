/**
 * Local Database of Popular Legitimate Domains.
 * Curated from public web rankings (Tranco, Cloudflare Radar, Cisco Umbrella, Alexa top datasets).
 * Covers top global domains and major regional sites (including Amazon India, Google, Microsoft,
 * Apple, GitHub, YouTube, Wikipedia, Indian utilities, banking, tech, media, and commerce).
 *
 * All entries are stored as lowercased registered domains for exact O(1) Set lookups.
 */

const RAW_TOP_DOMAINS = [
  // Top Global Tech Giants & Ecosystems
  'google.com', 'google.co.in', 'google.co.uk', 'google.de', 'google.fr', 'google.co.jp', 'google.ca', 'google.com.br', 'google.es', 'google.it', 'google.ru', 'google.com.au', 'google.nl', 'google.pl', 'google.co.id', 'google.com.tw', 'google.com.mx', 'google.com.tr', 'google.co.th', 'google.com.ar', 'google.co.za', 'google.com.eg', 'google.com.sa', 'google.com.pk', 'google.com.ng', 'google.com.ph', 'google.com.bd', 'google.com.my', 'google.co.nz',
  'googleapis.com', 'googleusercontent.com', 'gstatic.com', 'googlevideo.com', 'gmail.com', 'appspot.com',

  // Amazon Global & Regional Ecosystem
  'amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.co.jp', 'amazon.fr', 'amazon.it', 'amazon.es', 'amazon.ca', 'amazon.com.au', 'amazon.com.br', 'amazon.com.mx', 'amazon.nl', 'amazon.sg', 'amazon.ae', 'amazon.sa', 'amazon.se', 'amazon.pl', 'amazon.com.tr',
  'amazonaws.com', 'cloudfront.net', 'media-amazon.com', 'ssl-images-amazon.com', 'primevideo.com', 'a2z.com',

  // Microsoft Global Ecosystem
  'microsoft.com', 'live.com', 'office.com', 'bing.com', 'msn.com', 'azure.com', 'windows.com', 'xbox.com', 'visualstudio.com', 'linkedin.com', 'skype.com', 'microsoftonline.com', 'sharepoint.com', 'office365.com', 'outlook.com', 'onedrive.com', 'licdn.com', 'windowsupdate.com', 'azurewebsites.net', 'microsoftstore.com', 'msecnd.net',

  // Apple Ecosystem
  'apple.com', 'icloud.com', 'apple.news', 'itunes.com', 'cdn-apple.com', 'aaplimg.com', 'mzstatic.com',

  // Developer & Software Platforms
  'github.com', 'github.io', 'githubassets.com', 'githubusercontent.com', 'gitlab.com', 'bitbucket.org', 'stackoverflow.com', 'stackexchange.com', 'superuser.com', 'serverfault.com', 'askubuntu.com', 'npmjs.com', 'npmjs.org', 'npm.im', 'pypi.org', 'python.org', 'docker.com', 'docker.io', 'kubernetes.io', 'golang.org', 'rust-lang.org', 'nodejs.org', 'ruby-lang.org', 'oracle.com', 'java.com', 'apache.org', 'mozilla.org', 'w3.org', 'ietf.org', 'cisco.com', 'ibm.com', 'redhat.com', 'debian.org', 'ubuntu.com', 'centos.org', 'kernel.org', 'archlinux.org', 'alpinelinux.org', 'sourceforge.net', 'codepen.io', 'replit.com', 'huggingface.co', 'kaggle.com', 'arxiv.org',

  // Video, Media & Streaming
  'youtube.com', 'youtu.be', 'ytimg.com', 'netflix.com', 'nflxvideo.net', 'nflximg.net', 'spotify.com', 'scdn.co', 'twitch.tv', 'ttvnw.net', 'vimeo.com', 'vimeocdn.com', 'dailymotion.com', 'disneyplus.com', 'hulu.com', 'hbomax.com', 'max.com', 'hotstar.com', 'paramountplus.com', 'soundcloud.com', 'deezer.com', 'bandcamp.com',

  // Knowledge, Reference & Education
  'wikipedia.org', 'wikimedia.org', 'wiktionary.org', 'wikidata.org', 'wikiquote.org', 'wikibooks.org', 'wikisource.org', 'wikiversity.org', 'wikinews.org', 'wikivoyage.org', 'mediawiki.org',
  'archive.org', 'britannica.com', 'dictionary.com', 'merriam-webster.com', 'thesaurus.com', 'investopedia.com', 'quora.com', 'medium.com', 'ted.com', 'khanacademy.org', 'coursera.org', 'edx.org', 'udemy.com', 'duolingo.com', 'mit.edu', 'stanford.edu', 'harvard.edu', 'berkeley.edu', 'columbia.edu', 'ox.ac.uk', 'cam.ac.uk', 'cern.ch', 'nih.gov', 'cdc.gov', 'who.int', 'nasa.gov', 'nature.com', 'sciencedirect.com', 'springer.com', 'wiley.com', 'ieee.org', 'acm.org', 'jstor.org', 'researchgate.net', 'academia.edu',

  // Social & Messaging Platforms
  'facebook.com', 'fb.com', 'fbcdn.net', 'instagram.com', 'cdninstagram.com', 'whatsapp.com', 'whatsapp.net', 'messenger.com', 'meta.com', 'threads.net',
  'twitter.com', 'x.com', 't.co', 'twimg.com',
  'reddit.com', 'redd.it', 'redditmedia.com',
  'pinterest.com', 'pinimg.com', 'tumblr.com', 'snapchat.com', 'tiktok.com', 'tiktokcdn.com', 'byteoversea.com', 'telegram.org', 't.me', 'discord.com', 'discord.gg', 'discordapp.com', 'slack.com', 'zoom.us', 'viber.com', 'signal.org', 'wechat.com', 'line.me', 'mastodon.social',

  // Infrastructure, CDN, DNS, Security
  'cloudflare.com', 'cloudflare-dns.com', 'cloudflareinsights.com', 'fastly.net', 'fastlylb.net', 'akamai.com', 'akamaihd.net', 'akamaized.net', 'edgekey.net', 'edgesuite.net', 'digicert.com', 'letsencrypt.org', 'sectigo.com', 'verisign.com', 'iana.org', 'icann.org', 'quad9.net', 'opendns.com', 'virustotal.com', 'shodan.io', 'abuse.ch', 'urlhaus.abuse.ch', 'spamhaus.org',

  // Search Engines & Web Portals
  'yahoo.com', 'yahoo.co.jp', 'yimg.com', 'duckduckgo.com', 'bing.net', 'baidu.com', 'bdstatic.com', 'yandex.ru', 'yandex.com', 'brave.com', 'startpage.com', 'ecosia.org', 'ask.com', 'aol.com', 'naver.com', 'daum.net', 'sogou.com', 'seznam.cz',

  // E-commerce, Retail & Marketplaces (Global & Regional)
  'ebay.com', 'ebay.co.uk', 'ebay.de', 'ebay.in', 'walmart.com', 'target.com', 'aliexpress.com', 'alibaba.com', 'taobao.com', 'tmall.com', 'jd.com', 'rakuten.co.jp', 'rakuten.com', 'mercadolibre.com', 'mercadolivre.com.br', 'etsy.com', 'bestbuy.com', 'homedepot.com', 'ikea.com', 'costco.com', 'shopify.com', 'myshopify.com', 'wayfair.com', 'overstock.com', 'newegg.com', 'asos.com', 'shein.com', 'zara.com', 'hm.com',

  // Major Indian Services (E-Commerce, Government, Banking, Utilities, Media)
  'flipkart.com', 'myntra.com', 'meesho.com', 'jiomart.com', 'jio.com', 'reliancedigital.com', 'reliance.com', 'tata.com', 'tatacliq.com', 'tataneu.com', 'snapdeal.com', 'nykaa.com', 'ajio.com', 'firstcry.com', 'purplle.com', 'lenskart.com', 'bigbasket.com', 'blinkit.com', 'zeptonow.com',
  'irctc.co.in', 'indianrail.gov.in', 'railnet.gov.in',
  'gov.in', 'nic.in', 'uidai.gov.in', 'incometax.gov.in', 'gst.gov.in', 'digilocker.gov.in', 'cowin.gov.in', 'epfindia.gov.in', 'parivahan.gov.in', 'passportindia.gov.in', 'eci.gov.in', 'mca.gov.in', 'cbic.gov.in', 'upsc.gov.in', 'ssc.nic.in', 'nta.ac.in', 'india.gov.in', 'mygov.in',
  'sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com', 'hdfcbank.com', 'icicibank.com', 'axisbank.com', 'kotak.com', 'punjabnationalbank.in', 'pnbindia.in', 'bankofbaroda.in', 'bankofbaroda.com', 'canarabank.com', 'unionbankofindia.co.in', 'bankofindia.co.in', 'indusind.com', 'yesbank.in', 'idfcfirstbank.com', 'rbi.org.in', 'npci.org.in',
  'paytm.com', 'phonepe.com', 'razorpay.com', 'billdesk.com', 'cred.club', 'bseindia.com', 'nseindia.com', 'zerodha.com', 'groww.in', 'upstox.com', 'angelone.in', '5paisa.com',
  'airtel.in', 'airtel.com', 'myvi.in', 'bsnl.co.in',
  'swiggy.com', 'zomato.com', 'olaelectric.com', 'olacabs.com', 'rapido.bike', 'makemytrip.com', 'goibibo.com', 'cleartrip.com', 'ixigo.com', 'redbus.in', 'yatra.com', 'bookmyshow.com',
  'naukri.com', 'foundit.in', 'shiksha.com', 'shaadi.com', 'jeevansathi.com', 'bharatmatrimony.com', '99acres.com', 'magicbricks.com', 'housing.com', 'nobroker.in',
  'indiatimes.com', 'economictimes.indiatimes.com', 'timesofindia.indiatimes.com', 'thehindu.com', 'hindustantimes.com', 'indianexpress.com', 'ndtv.com', 'moneycontrol.com', 'livemint.com', 'news18.com', 'indiatoday.in', 'aajtak.in', 'zeenews.india.com', 'bhaskar.com', 'jagran.com', 'cricbuzz.com', 'espncricinfo.com',

  // Global News, Media & Journalism
  'nytimes.com', 'bbc.co.uk', 'bbc.com', 'cnn.com', 'reuters.com', 'bloomberg.com', 'theguardian.com', 'washingtonpost.com', 'forbes.com', 'wsj.com', 'apnews.com', 'cnbc.com', 'ft.com', 'economist.com', 'time.com', 'usatoday.com', 'latimes.com', 'npr.org', 'cbsnews.com', 'nbcnews.com', 'abcnews.go.com', 'foxnews.com', 'aljazeera.com', 'dw.com', 'france24.com', 'lemonde.fr', 'spiegel.de', 'elpais.com', 'corriere.it', 'nikkei.com', 'asahi.com', 'scmp.com', 'straitstimes.com', 'techcrunch.com', 'theverge.com', 'wired.com', 'engadget.com', 'arstechnica.com', 'gizmodo.com', 'cnet.com', 'zdnet.com',

  // Global Financial Institutions & Payment Processors
  'paypal.com', 'paypalobjects.com', 'stripe.com', 'square.com', 'squareup.com', 'block.xyz', 'visa.com', 'mastercard.com', 'americanexpress.com', 'discover.com', 'jpmorganchase.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citigroup.com', 'citi.com', 'capitalone.com', 'goldmansachs.com', 'morganstanley.com', 'barclays.co.uk', 'hsbc.com', 'hsbc.co.uk', 'db.com', 'ubs.com', 'credit-suisse.com', 'santander.com', 'bnpparibas.com', 'fidelity.com', 'schwab.com', 'vanguard.com', 'blackrock.com', 'robinhood.com', 'coinbase.com', 'binance.com', 'kraken.com', 'gemini.com', 'bitstamp.net',

  // Enterprise Software, Productivity & SaaS
  'salesforce.com', 'force.com', 'adobe.com', 'adobe.io', 'atlassian.com', 'atlassian.net', 'jira.com', 'trello.com', 'notion.so', 'figma.com', 'canva.com', 'dropbox.com', 'box.com', 'zendesk.com', 'servicenow.com', 'workday.com', 'intuit.com', 'quickbooks.com', 'turbotax.com', 'hubspot.com', 'mailchimp.com', 'docusign.com', 'hellosign.com', 'asana.com', 'monday.com', 'airtable.com', 'linear.app', 'zapier.com', 'segment.com', 'datadoghq.com', 'newrelic.com', 'sentry.io', 'splunk.com', 'elastic.co', 'pagerduty.com', 'gitlab.io', 'vercel.com', 'vercel.app', 'netlify.app', 'netlify.com', 'render.com', 'heroku.com', 'railway.app', 'fly.io', 'supabase.com',

  // Travel, Hospitality & Transport
  'booking.com', 'airbnb.com', 'tripadvisor.com', 'expedia.com', 'kayak.com', 'hotels.com', 'agoda.com', 'uber.com', 'lyft.com', 'flightradar24.com', 'skyscanner.net', 'delta.com', 'united.com', 'aa.com', 'southwest.com', 'emirates.com', 'qatarairways.com', 'singaporeair.com', 'britishairways.com', 'lufthansa.com', 'airfrance.com', 'airindia.com', 'indigo.in', 'goindigo.in',

  // Gaming Platforms & Services
  'steampowered.com', 'steamcommunity.com', 'epicgames.com', 'ea.com', 'ubisoft.com', 'playstation.com', 'sony.com', 'nintendo.com', 'xboxlive.com', 'roblox.com', 'blizzard.com', 'battle.net', 'riotgames.com', 'leagueoflegends.com', 'rockstargames.com', 'ign.com', 'gamespot.com', 'polygon.com', 'kotaku.com'
];

export const TOP_LEGITIMATE_DOMAINS = new Set(RAW_TOP_DOMAINS.map(d => d.toLowerCase().trim()));

/**
 * High-profile brand targets for typosquatting and brand spoofing detection.
 * Maps the target brand name to its primary legitimate registered domains.
 */
export const TARGET_BRANDS = {
  amazon: {
    canonical: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.co.jp', 'amazon.fr', 'amazon.ca'],
    name: 'Amazon'
  },
  google: {
    canonical: ['google.com', 'google.co.in', 'google.co.uk', 'google.de', 'google.fr', 'google.co.jp'],
    name: 'Google'
  },
  microsoft: {
    canonical: ['microsoft.com', 'live.com', 'office.com', 'bing.com', 'azure.com'],
    name: 'Microsoft'
  },
  apple: {
    canonical: ['apple.com', 'icloud.com'],
    name: 'Apple'
  },
  paypal: {
    canonical: ['paypal.com'],
    name: 'PayPal'
  },
  github: {
    canonical: ['github.com', 'github.io'],
    name: 'GitHub'
  },
  netflix: {
    canonical: ['netflix.com'],
    name: 'Netflix'
  },
  facebook: {
    canonical: ['facebook.com', 'fb.com'],
    name: 'Facebook / Meta'
  },
  instagram: {
    canonical: ['instagram.com'],
    name: 'Instagram'
  },
  whatsapp: {
    canonical: ['whatsapp.com'],
    name: 'WhatsApp'
  },
  youtube: {
    canonical: ['youtube.com', 'youtu.be'],
    name: 'YouTube'
  },
  wikipedia: {
    canonical: ['wikipedia.org', 'wikimedia.org'],
    name: 'Wikipedia'
  },
  chase: {
    canonical: ['chase.com'],
    name: 'Chase Bank'
  },
  wellsfargo: {
    canonical: ['wellsfargo.com'],
    name: 'Wells Fargo'
  },
  bankofamerica: {
    canonical: ['bankofamerica.com'],
    name: 'Bank of America'
  },
  sbi: {
    canonical: ['sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com'],
    name: 'State Bank of India (SBI)'
  },
  hdfc: {
    canonical: ['hdfcbank.com'],
    name: 'HDFC Bank'
  },
  icici: {
    canonical: ['icicibank.com'],
    name: 'ICICI Bank'
  },
  flipkart: {
    canonical: ['flipkart.com'],
    name: 'Flipkart'
  },
  binance: {
    canonical: ['binance.com'],
    name: 'Binance'
  },
  coinbase: {
    canonical: ['coinbase.com'],
    name: 'Coinbase'
  },
  metamask: {
    canonical: ['metamask.io'],
    name: 'MetaMask'
  },
  twitter: {
    canonical: ['twitter.com', 'x.com'],
    name: 'Twitter / X'
  },
  linkedin: {
    canonical: ['linkedin.com'],
    name: 'LinkedIn'
  },
  adobe: {
    canonical: ['adobe.com'],
    name: 'Adobe'
  },
  dropbox: {
    canonical: ['dropbox.com'],
    name: 'Dropbox'
  },
  irctc: {
    canonical: ['irctc.co.in'],
    name: 'IRCTC Official'
  }
};

/**
 * Check if a registered domain is in the top legitimate domains database.
 * @param {string} registeredDomain
 * @returns {object} { isTopDomain: boolean, domain: string, brand?: object }
 */
export function isRecognizedTopDomain(registeredDomain) {
  const norm = String(registeredDomain || '').toLowerCase().trim();
  if (TOP_LEGITIMATE_DOMAINS.has(norm)) {
    // Find matching brand metadata if available
    for (const [brandKey, meta] of Object.entries(TARGET_BRANDS)) {
      if (meta.canonical.includes(norm)) {
        return { isTopDomain: true, domain: norm, brand: meta.name };
      }
    }
    return { isTopDomain: true, domain: norm };
  }
  return { isTopDomain: false, domain: norm };
}
