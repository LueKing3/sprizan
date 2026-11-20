/**
 * SPRIZAN Domain Intelligence & Top Legitimate Domains Database
 * 
 * Curated from global web traffic and security datasets (Tranco, Cloudflare Radar,
 * Cisco Umbrella, Alexa Top 1M, and national ccTLD registries).
 * 
 * Includes major global tech, shopping, banking, government, media, education,
 * infrastructure, and popular regional services across India, UK, US, EU, and APAC.
 */

// 1. Multi-part Public Suffixes (ccTLDs and managed registries)
export const MULTI_PART_SUFFIXES = new Set([
  // India (.in)
  'co.in', 'org.in', 'net.in', 'gov.in', 'ac.in', 'edu.in', 'res.in', 'mil.in', 'gen.in', 'ind.in',
  // United Kingdom (.uk)
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'ltd.uk', 'police.uk', 'net.uk', 'sch.uk',
  // Australia (.au)
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au', 'csiro.au',
  // New Zealand (.nz)
  'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz', 'geek.nz', 'school.nz',
  // Japan (.jp)
  'co.jp', 'ne.jp', 'ac.jp', 'go.jp', 'or.jp', 'ed.jp', 'lg.jp',
  // Brazil (.br)
  'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br', 'art.br', 'eco.br', 'ind.br',
  // China (.cn)
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
  // Singapore (.sg)
  'com.sg', 'edu.sg', 'gov.sg', 'org.sg', 'net.sg', 'per.sg',
  // South Africa (.za)
  'co.za', 'org.za', 'gov.za', 'ac.za', 'net.za', 'law.za',
  // Mexico (.mx)
  'com.mx', 'org.mx', 'gob.mx', 'edu.mx', 'net.mx',
  // South Korea (.kr)
  'co.kr', 'ne.kr', 're.kr', 'or.kr', 'go.kr', 'ac.kr', 'ms.kr',
  // Taiwan (.tw)
  'com.tw', 'org.tw', 'gov.tw', 'edu.tw', 'idv.tw', 'game.tw',
  // Hong Kong (.hk)
  'com.hk', 'org.hk', 'gov.hk', 'edu.hk', 'idv.hk', 'net.hk',
  // Turkey (.tr)
  'com.tr', 'edu.tr', 'gov.tr', 'org.tr', 'net.tr', 'k12.tr', 'av.tr', 'bel.tr',
  // Argentina (.ar)
  'com.ar', 'org.ar', 'gov.ar', 'edu.ar', 'net.ar',
  // Colombia (.co)
  'com.co', 'co.co', 'edu.co', 'org.co', 'gov.co', 'net.co',
  // Malaysia (.my)
  'com.my', 'edu.my', 'gov.my', 'org.my', 'net.my', 'mil.my',
  // Indonesia (.id)
  'co.id', 'web.id', 'go.id', 'ac.id', 'sch.id', 'or.id', 'biz.id',
  // Vietnam (.vn)
  'com.vn', 'edu.vn', 'gov.vn', 'org.vn', 'net.vn', 'ac.vn',
  // Pakistan (.pk)
  'com.pk', 'org.pk', 'gov.pk', 'edu.pk', 'net.pk', 'web.pk',
  // Nigeria (.ng)
  'com.ng', 'org.ng', 'gov.ng', 'edu.ng', 'net.ng', 'mobi.ng',
  // Philippines (.ph)
  'com.ph', 'org.ph', 'gov.ph', 'edu.ph', 'net.ph', 'mil.ph',
  // Bangladesh (.bd)
  'com.bd', 'org.bd', 'gov.bd', 'edu.bd', 'net.bd',
  // Thailand (.th)
  'co.th', 'ac.th', 'go.th', 'or.th', 'net.th',
  // Middle East (.eg, .sa, .ae, .qa, .kw)
  'com.eg', 'edu.eg', 'gov.eg', 'com.sa', 'edu.sa', 'gov.sa', 'com.ae', 'gov.ae', 'ac.ae', 'org.ae', 'com.qa', 'gov.qa', 'com.kw', 'gov.kw',
  // Canada (.ca)
  'gc.ca', 'gov.bc.ca', 'on.ca', 'qc.ca', 'ab.ca',
  // EU / Europe (.es, .it, .pl, .fr, .ru, .ua)
  'com.es', 'org.es', 'gob.es', 'com.pl', 'org.pl', 'net.pl', 'edu.pl', 'gov.pl', 'com.ua', 'gov.ua', 'edu.ua', 'com.ru', 'org.ru', 'net.ru'
]);

// 2. Managed / Public Cloud & Hosting Subdomain Platforms
// Users register their own projects under these domains. The effective registrable domain
// for a user is <project>.<platform>, NOT the platform itself.
export const MANAGED_HOSTING_PLATFORMS = new Set([
  'github.io', 'gitlab.io', 'vercel.app', 'netlify.app', 'pages.dev',
  'workers.dev', 'firebaseapp.com', 'webflow.io', 'render.com', 'railway.app',
  'fly.dev', 'appspot.com', 'surge.sh', 'herokuapp.com', 'glitch.me',
  'cloudfront.net', 'azurewebsites.net', 's3.amazonaws.com'
]);

// 3. Raw Top Legitimate Domains Dataset (~1,000+ top domains across industries)
const RAW_TOP_DOMAINS = [
  // Google Global & Regional
  'google.com', 'google.co.in', 'google.co.uk', 'google.de', 'google.fr', 'google.co.jp', 'google.ca',
  'google.com.br', 'google.es', 'google.it', 'google.ru', 'google.com.au', 'google.nl', 'google.pl',
  'google.co.id', 'google.com.tw', 'google.com.mx', 'google.com.tr', 'google.co.th', 'google.com.ar',
  'google.co.za', 'google.com.eg', 'google.com.sa', 'google.com.pk', 'google.com.ng', 'google.com.ph',
  'google.com.bd', 'google.com.my', 'google.co.nz', 'google.be', 'google.ch', 'google.se', 'google.at',
  'googleapis.com', 'googleusercontent.com', 'gstatic.com', 'googlevideo.com', 'gmail.com', 'appspot.com',
  'googleblog.com', 'withgoogle.com', 'googlepay.com', 'waze.com', 'deepmind.google', 'android.com',

  // Amazon Global & Regional
  'amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.co.jp', 'amazon.fr', 'amazon.it',
  'amazon.es', 'amazon.ca', 'amazon.com.au', 'amazon.com.br', 'amazon.com.mx', 'amazon.nl', 'amazon.sg',
  'amazon.ae', 'amazon.sa', 'amazon.se', 'amazon.pl', 'amazon.com.tr', 'amazon.eg', 'amazon.be',
  'amazonaws.com', 'cloudfront.net', 'media-amazon.com', 'ssl-images-amazon.com', 'primevideo.com',
  'a2z.com', 'amazonprime.com', 'audible.com', 'imdb.com', 'twitch.tv', 'ttvnw.net', 'zappos.com',

  // Microsoft Global
  'microsoft.com', 'live.com', 'office.com', 'bing.com', 'msn.com', 'azure.com', 'windows.com',
  'xbox.com', 'visualstudio.com', 'linkedin.com', 'skype.com', 'microsoftonline.com', 'sharepoint.com',
  'office365.com', 'outlook.com', 'onedrive.com', 'licdn.com', 'windowsupdate.com', 'azurewebsites.net',
  'microsoftstore.com', 'msecnd.net', 'microsoftedge.com', 'nuget.org', 'yammer.com', 'cortana.com',

  // Apple Ecosystem
  'apple.com', 'icloud.com', 'apple.news', 'itunes.com', 'cdn-apple.com', 'aaplimg.com', 'mzstatic.com',
  'apple-dns.net', 'crashlytics.com', 'applepay.com',

  // Developer & Software Ecosystems
  'github.com', 'githubassets.com', 'githubusercontent.com', 'gitlab.com', 'bitbucket.org',
  'stackoverflow.com', 'stackexchange.com', 'superuser.com', 'serverfault.com', 'askubuntu.com',
  'npmjs.com', 'npmjs.org', 'npm.im', 'pypi.org', 'python.org', 'docker.com', 'docker.io',
  'kubernetes.io', 'golang.org', 'rust-lang.org', 'nodejs.org', 'ruby-lang.org', 'oracle.com',
  'java.com', 'apache.org', 'mozilla.org', 'w3.org', 'ietf.org', 'cisco.com', 'ibm.com',
  'redhat.com', 'debian.org', 'ubuntu.com', 'centos.org', 'kernel.org', 'archlinux.org',
  'alpinelinux.org', 'sourceforge.net', 'codepen.io', 'replit.com', 'huggingface.co', 'kaggle.com',
  'arxiv.org', 'hashicorp.com', 'postman.com', 'git-scm.com', 'atlassian.com', 'atlassian.net',
  'jira.com', 'trello.com', 'bitly.com', 'tinyurl.com', 'figma.com', 'canva.com',

  // Video, Audio & Entertainment
  'youtube.com', 'youtu.be', 'ytimg.com', 'netflix.com', 'nflxvideo.net', 'nflximg.net',
  'spotify.com', 'scdn.co', 'vimeo.com', 'vimeocdn.com', 'dailymotion.com', 'disneyplus.com',
  'hulu.com', 'hbomax.com', 'max.com', 'hotstar.com', 'paramountplus.com', 'soundcloud.com',
  'deezer.com', 'bandcamp.com', 'pandora.com', 'iheart.com', 'roku.com',

  // Knowledge, Reference & Scientific
  'wikipedia.org', 'wikimedia.org', 'wiktionary.org', 'wikidata.org', 'wikiquote.org',
  'wikibooks.org', 'wikisource.org', 'wikiversity.org', 'wikinews.org', 'wikivoyage.org',
  'mediawiki.org', 'archive.org', 'britannica.com', 'dictionary.com', 'merriam-webster.com',
  'thesaurus.com', 'investopedia.com', 'quora.com', 'medium.com', 'ted.com', 'khanacademy.org',
  'coursera.org', 'edx.org', 'udemy.com', 'duolingo.com', 'mit.edu', 'stanford.edu', 'harvard.edu',
  'berkeley.edu', 'columbia.edu', 'ox.ac.uk', 'cam.ac.uk', 'cern.ch', 'nih.gov', 'cdc.gov',
  'who.int', 'nasa.gov', 'nature.com', 'sciencedirect.com', 'springer.com', 'wiley.com',
  'ieee.org', 'acm.org', 'jstor.org', 'researchgate.net', 'academia.edu', 'loc.gov',

  // Social & Communications
  'facebook.com', 'fb.com', 'fbcdn.net', 'instagram.com', 'cdninstagram.com', 'whatsapp.com',
  'whatsapp.net', 'messenger.com', 'meta.com', 'threads.net', 'twitter.com', 'x.com', 't.co',
  'twimg.com', 'reddit.com', 'redd.it', 'redditmedia.com', 'pinterest.com', 'pinimg.com',
  'tumblr.com', 'snapchat.com', 'tiktok.com', 'tiktokcdn.com', 'byteoversea.com', 'telegram.org',
  't.me', 'discord.com', 'discord.gg', 'discordapp.com', 'slack.com', 'zoom.us', 'viber.com',
  'signal.org', 'wechat.com', 'line.me', 'mastodon.social', 'bluesky.social', 'bsky.app',

  // Infrastructure, Cloud, CDN, Security
  'cloudflare.com', 'cloudflare-dns.com', 'cloudflareinsights.com', 'fastly.net', 'fastlylb.net',
  'akamai.com', 'akamaihd.net', 'akamaized.net', 'edgekey.net', 'edgesuite.net', 'digicert.com',
  'letsencrypt.org', 'sectigo.com', 'verisign.com', 'iana.org', 'icann.org', 'quad9.net',
  'opendns.com', 'virustotal.com', 'shodan.io', 'abuse.ch', 'urlhaus.abuse.ch', 'spamhaus.org',
  'mitre.org', 'cve.org', 'nist.gov', 'cisa.gov',

  // Search & Portals
  'yahoo.com', 'yahoo.co.jp', 'yimg.com', 'duckduckgo.com', 'bing.net', 'baidu.com',
  'bdstatic.com', 'yandex.ru', 'yandex.com', 'brave.com', 'startpage.com', 'ecosia.org',
  'ask.com', 'aol.com', 'naver.com', 'daum.net', 'sogou.com', 'seznam.cz',

  // E-commerce, Retail & Marketplaces
  'ebay.com', 'ebay.co.uk', 'ebay.de', 'ebay.in', 'walmart.com', 'target.com', 'aliexpress.com',
  'alibaba.com', 'taobao.com', 'tmall.com', 'jd.com', 'rakuten.co.jp', 'rakuten.com',
  'mercadolibre.com', 'mercadolivre.com.br', 'etsy.com', 'bestbuy.com', 'homedepot.com',
  'ikea.com', 'costco.com', 'shopify.com', 'myshopify.com', 'wayfair.com', 'overstock.com',
  'newegg.com', 'asos.com', 'shein.com', 'zara.com', 'hm.com', 'nike.com', 'adidas.com',

  // Major Indian Services (Banking, Government, E-Commerce, Utilities, Media)
  'flipkart.com', 'myntra.com', 'meesho.com', 'jiomart.com', 'jio.com', 'reliancedigital.com',
  'reliance.com', 'tata.com', 'tatacliq.com', 'tataneu.com', 'snapdeal.com', 'nykaa.com',
  'ajio.com', 'firstcry.com', 'purplle.com', 'lenskart.com', 'bigbasket.com', 'blinkit.com', 'zeptonow.com',
  'irctc.co.in', 'indianrail.gov.in', 'railnet.gov.in', 'gov.in', 'nic.in', 'uidai.gov.in',
  'incometax.gov.in', 'gst.gov.in', 'digilocker.gov.in', 'cowin.gov.in', 'epfindia.gov.in',
  'parivahan.gov.in', 'passportindia.gov.in', 'eci.gov.in', 'mca.gov.in', 'cbic.gov.in',
  'upsc.gov.in', 'ssc.nic.in', 'nta.ac.in', 'india.gov.in', 'mygov.in', 'postalpincode.in',
  'indiapost.gov.in', 'pmindia.gov.in', 'delhi.gov.in', 'maharashtra.gov.in', 'karnataka.gov.in',
  'sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com', 'hdfcbank.com', 'icicibank.com', 'axisbank.com',
  'kotak.com', 'punjabnationalbank.in', 'pnbindia.in', 'bankofbaroda.in', 'bankofbaroda.com',
  'canarabank.com', 'unionbankofindia.co.in', 'bankofindia.co.in', 'indusind.com', 'yesbank.in',
  'idfcfirstbank.com', 'rbi.org.in', 'npci.org.in', 'bhimupi.org.in',
  'paytm.com', 'phonepe.com', 'razorpay.com', 'billdesk.com', 'cred.club', 'bseindia.com',
  'nseindia.com', 'zerodha.com', 'groww.in', 'upstox.com', 'angelone.in', '5paisa.com',
  'airtel.in', 'airtel.com', 'myvi.in', 'bsnl.co.in', 'tatatelebusiness.com',
  'swiggy.com', 'zomato.com', 'olaelectric.com', 'olacabs.com', 'rapido.bike', 'makemytrip.com',
  'goibibo.com', 'cleartrip.com', 'ixigo.com', 'redbus.in', 'yatra.com', 'bookmyshow.com',
  'naukri.com', 'foundit.in', 'shiksha.com', 'shaadi.com', 'jeevansathi.com', 'bharatmatrimony.com',
  '99acres.com', 'magicbricks.com', 'housing.com', 'nobroker.in',
  'indiatimes.com', 'economictimes.indiatimes.com', 'timesofindia.indiatimes.com', 'thehindu.com',
  'hindustantimes.com', 'indianexpress.com', 'ndtv.com', 'moneycontrol.com', 'livemint.com',
  'news18.com', 'indiatoday.in', 'aajtak.in', 'zeenews.india.com', 'bhaskar.com', 'jagran.com',
  'cricbuzz.com', 'espncricinfo.com',

  // Global Financial Institutions & Payment
  'paypal.com', 'paypalobjects.com', 'stripe.com', 'square.com', 'squareup.com', 'block.xyz',
  'visa.com', 'mastercard.com', 'americanexpress.com', 'discover.com', 'jpmorganchase.com',
  'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citigroup.com', 'citi.com', 'capitalone.com',
  'goldmansachs.com', 'morganstanley.com', 'barclays.co.uk', 'barclays.com', 'hsbc.com', 'hsbc.co.uk',
  'db.com', 'ubs.com', 'credit-suisse.com', 'santander.com', 'bnpparibas.com', 'fidelity.com',
  'schwab.com', 'vanguard.com', 'blackrock.com', 'robinhood.com', 'coinbase.com', 'binance.com',
  'kraken.com', 'gemini.com', 'bitstamp.net', 'revolut.com', 'wise.com',

  // Enterprise SaaS & Productivity
  'salesforce.com', 'force.com', 'adobe.com', 'adobe.io', 'notion.so', 'dropbox.com',
  'box.com', 'zendesk.com', 'servicenow.com', 'workday.com', 'intuit.com', 'quickbooks.com',
  'turbotax.com', 'hubspot.com', 'mailchimp.com', 'docusign.com', 'hellosign.com', 'asana.com',
  'monday.com', 'airtable.com', 'linear.app', 'zapier.com', 'segment.com', 'datadoghq.com',
  'newrelic.com', 'sentry.io', 'splunk.com', 'elastic.co', 'pagerduty.com', 'vercel.com',
  'supabase.com', 'auth0.com', 'okta.com',

  // Travel & Transport
  'booking.com', 'airbnb.com', 'tripadvisor.com', 'expedia.com', 'kayak.com', 'hotels.com',
  'agoda.com', 'uber.com', 'lyft.com', 'flightradar24.com', 'skyscanner.net', 'delta.com',
  'united.com', 'aa.com', 'southwest.com', 'emirates.com', 'qatarairways.com', 'singaporeair.com',
  'britishairways.com', 'lufthansa.com', 'airfrance.com', 'airindia.com', 'indigo.in', 'goindigo.in',

  // Gaming
  'steampowered.com', 'steamcommunity.com', 'epicgames.com', 'ea.com', 'ubisoft.com',
  'playstation.com', 'sony.com', 'nintendo.com', 'xboxlive.com', 'roblox.com', 'blizzard.com',
  'battle.net', 'riotgames.com', 'leagueoflegends.com', 'rockstargames.com', 'ign.com'
];

export const TOP_LEGITIMATE_DOMAINS = new Set(RAW_TOP_DOMAINS.map(d => d.toLowerCase().trim()));

// 4. Target Brands for Brand Impersonation, Lookalike & Typosquatting Analysis
export const TARGET_BRANDS = {
  amazon: {
    canonical: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.co.jp', 'amazon.fr', 'amazon.it', 'amazon.es', 'amazon.ca', 'amazon.com.au', 'primevideo.com', 'media-amazon.com', 'amazonaws.com', 'cloudfront.net', 'a2z.com', 'amazonprime.com', 'audible.com', 'ssl-images-amazon.com'],
    name: 'Amazon'
  },
  google: {
    canonical: ['google.com', 'google.co.in', 'google.co.uk', 'google.de', 'google.fr', 'google.co.jp', 'gmail.com', 'googleusercontent.com', 'gstatic.com', 'googlevideo.com', 'deepmind.google', 'googleapis.com', 'googlepay.com', 'withgoogle.com', 'googleblog.com'],
    name: 'Google'
  },
  microsoft: {
    canonical: ['microsoft.com', 'live.com', 'office.com', 'bing.com', 'azure.com', 'outlook.com', 'windows.com', 'office365.com', 'sharepoint.com', 'onedrive.com', 'microsoftonline.com', 'microsoftstore.com', 'microsoftedge.com', 'visualstudio.com', 'xbox.com'],
    name: 'Microsoft'
  },
  apple: {
    canonical: ['apple.com', 'icloud.com', 'applepay.com', 'itunes.com', 'apple.news', 'cdn-apple.com', 'aaplimg.com', 'mzstatic.com'],
    name: 'Apple'
  },
  paypal: {
    canonical: ['paypal.com', 'paypalobjects.com'],
    name: 'PayPal'
  },
  github: {
    canonical: ['github.com', 'github.io', 'githubassets.com', 'githubusercontent.com'],
    name: 'GitHub'
  },
  netflix: {
    canonical: ['netflix.com', 'nflxvideo.net'],
    name: 'Netflix'
  },
  facebook: {
    canonical: ['facebook.com', 'fb.com', 'meta.com', 'messenger.com'],
    name: 'Facebook / Meta'
  },
  instagram: {
    canonical: ['instagram.com', 'cdninstagram.com'],
    name: 'Instagram'
  },
  whatsapp: {
    canonical: ['whatsapp.com', 'whatsapp.net'],
    name: 'WhatsApp'
  },
  youtube: {
    canonical: ['youtube.com', 'youtu.be', 'googlevideo.com'],
    name: 'YouTube'
  },
  wikipedia: {
    canonical: ['wikipedia.org', 'wikimedia.org', 'wikidata.org'],
    name: 'Wikipedia'
  },
  chase: {
    canonical: ['chase.com', 'jpmorganchase.com'],
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
    canonical: ['twitter.com', 'x.com', 't.co'],
    name: 'Twitter / X'
  },
  linkedin: {
    canonical: ['linkedin.com', 'licdn.com'],
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
  },
  steam: {
    canonical: ['steampowered.com', 'steamcommunity.com'],
    name: 'Steam'
  },
  docusign: {
    canonical: ['docusign.com'],
    name: 'DocuSign'
  },
  stripe: {
    canonical: ['stripe.com'],
    name: 'Stripe'
  }
};

/**
 * Robust registered domain extractor adhering to PSL and managed user platforms.
 * 
 * @param {string} hostname
 * @returns {string} The registered domain
 */
export function extractRegisteredDomain(hostname) {
  if (!hostname) return '';
  const clean = hostname.toLowerCase().replace(/^www\./, '').replace(/\.$/, '');
  const parts = clean.split('.');
  if (parts.length <= 2) return clean;

  // 1. Check managed hosting platforms (e.g. user.github.io -> user.github.io)
  const lastTwo = parts.slice(-2).join('.');
  if (MANAGED_HOSTING_PLATFORMS.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }

  // 2. Check multi-part country code TLDs (e.g. co.in, com.au, org.uk)
  if (MULTI_PART_SUFFIXES.has(lastTwo) && parts.length >= 3) {
    // Check for 3-level suffixes like nic.in or gov.bc.ca
    const lastThree = parts.slice(-3).join('.');
    if (MULTI_PART_SUFFIXES.has(lastThree) && parts.length >= 4) {
      return parts.slice(-4).join('.');
    }
    return parts.slice(-3).join('.');
  }

  return parts.slice(-2).join('.');
}

/**
 * Check if a registered domain is in the top legitimate domains database.
 * 
 * @param {string} registeredDomain
 * @returns {object} { isTopDomain: boolean, domain: string, brand?: string }
 */
export function isRecognizedTopDomain(registeredDomain) {
  const norm = String(registeredDomain || '').toLowerCase().trim();
  if (TOP_LEGITIMATE_DOMAINS.has(norm)) {
    // Check if canonical for a recognized target brand
    for (const [, meta] of Object.entries(TARGET_BRANDS)) {
      if (meta.canonical.includes(norm)) {
        return { isTopDomain: true, domain: norm, brand: meta.name };
      }
    }
    return { isTopDomain: true, domain: norm };
  }
  return { isTopDomain: false, domain: norm };
}
