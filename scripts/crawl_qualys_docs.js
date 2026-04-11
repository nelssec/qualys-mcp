#!/usr/bin/env node
/**
 * Qualys API Documentation Crawler
 *
 * Crawls all Qualys API documentation pages, extracts API endpoints,
 * and saves structured data for gap analysis against our MCP implementation.
 *
 * Usage: npx playwright test scripts/crawl_qualys_docs.js
 *    or: node scripts/crawl_qualys_docs.js
 */

const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const OUTPUT_DIR = path.join(__dirname, '..', 'eval_results', 'api_crawl');
const MAX_PAGES = 2000;
const CONCURRENCY = 3;
const TIMEOUT = 15000;

const SEED_URLS = [
  // API User Guides (HTML docs)
  'https://docs.qualys.com/en/vm/api/index.htm',
  'https://docs.qualys.com/en/csam/latest/index.htm',
  'https://docs.qualys.com/en/tc/api/index.htm',
  'https://docs.qualys.com/en/cs/latest/index.htm',
  'https://docs.qualys.com/en/was/latest/index.htm',
  'https://docs.qualys.com/en/edr/latest/index.htm',
  'https://docs.qualys.com/en/etm/latest/index.htm',
  'https://docs.qualys.com/en/fim/latest/index.htm',
  'https://docs.qualys.com/en/pm/latest/index.htm',
  'https://docs.qualys.com/en/certview/latest/index.htm',
  'https://docs.qualys.com/en/ta/latest/index.htm',
  'https://docs.qualys.com/en/car/latest/index.htm',
  'https://docs.qualys.com/en/vmdr-ot/latest/index.htm',
  'https://docs.qualys.com/en/conn/latest/index.htm',
  'https://docs.qualys.com/en/saasdr/latest/index.htm',
  'https://docs.qualys.com/en/qflow/latest/index.htm',
  // Release notes (API-specific)
  'https://docs.qualys.com/en/vm/release-notes/qweb/release_10_38_api.htm',
  'https://docs.qualys.com/en/csam/release-notes/cybersecurity_asset_management/release_3_7_1_api.htm',
  'https://docs.qualys.com/en/tc/release-notes/totalcloud/release_2_22_api.htm',
  'https://docs.qualys.com/en/cs/release-notes/container_security/release_1_42_api.htm',
  'https://docs.qualys.com/en/pm/release-notes/patch_management/release_3_13_api.htm',
  'https://docs.qualys.com/en/ta/release-notes/total_ai/release_1_6_1_api.htm',
  'https://docs.qualys.com/en/ta/release-notes/total_ai/release_1_5_api.htm',
  'https://docs.qualys.com/en/edr/release-notes/endpoint_detection_and_response/release_3_8_1_api.htm',
  'https://docs.qualys.com/en/certview/release-notes/certview/release_4_7_api.htm',
  'https://docs.qualys.com/en/saasdr/release-notes/saasdr/release_1_14_0_api.htm',
  'https://docs.qualys.com/en/fim/release-notes/file_integrity_monitoring/release_4_8_1_api.htm',
];

// Patterns that indicate an API endpoint in the page
const ENDPOINT_PATTERNS = [
  /(?:GET|POST|PUT|DELETE|PATCH)\s+[\/\w\-\.{}]+/gi,
  /\/api\/\d+\.\d+\/fo\/[\w\/\-\.]+/gi,
  /\/rest\/\d+\.\d+\/[\w\/\-\.{}]+/gi,
  /\/qps\/rest\/\d+\.\d+\/[\w\/\-\.]+/gi,
  /\/csapi\/v[\d.]+\/[\w\/\-\.{}]+/gi,
  /\/cloudview-api\/rest\/v\d+\/[\w\/\-\.{}]+/gi,
  /\/pm\/v\d+\/[\w\/\-\.{}]+/gi,
  /\/mtg\/v\d+\/[\w\/\-\.{}]+/gi,
  /\/etm\/[\w\/\-\.{}]+/gi,
  /\/tai\/api\/[\d.]+\/[\w\/\-\.{}]+/gi,
  /\/ioc\/[\w\/\-\.{}]+/gi,
  /\/certview\/v[\d.]+\/[\w\/\-\.{}]+/gi,
  /\/cdr-api\/rest\/v\d+\/[\w\/\-\.{}]+/gi,
  /\/sdr\/api\/[\w\/\-\.{}]+/gi,
  /\/conn\/[\w\/\-\.{}]+/gi,
  /\/pcas\/v\d+\/[\w\/\-\.{}]+/gi,
];

async function extractFromPage(page, url) {
  const result = {
    url,
    title: '',
    endpoints: [],
    links: [],
    module: '',
    error: null,
  };

  try {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: TIMEOUT });

    result.title = await page.title();

    // Determine module from URL
    if (url.includes('/vm/')) result.module = 'VMDR';
    else if (url.includes('/csam/')) result.module = 'CSAM';
    else if (url.includes('/tc/')) result.module = 'TotalCloud';
    else if (url.includes('/cs/') || url.includes('/csapi')) result.module = 'ContainerSecurity';
    else if (url.includes('/was/')) result.module = 'WAS';
    else if (url.includes('/edr/')) result.module = 'EDR';
    else if (url.includes('/etm/')) result.module = 'ETM';
    else if (url.includes('/fim/')) result.module = 'FIM';
    else if (url.includes('/pm/')) result.module = 'PatchManagement';
    else if (url.includes('/certview/')) result.module = 'CertView';
    else if (url.includes('/ta/')) result.module = 'TotalAI';
    else if (url.includes('/car/')) result.module = 'CAR';
    else if (url.includes('/vmdr-ot/')) result.module = 'VMDR-OT';
    else if (url.includes('/conn/')) result.module = 'Connectors';
    else if (url.includes('/saasdr/')) result.module = 'SaaSDR';
    else if (url.includes('/qflow/')) result.module = 'QFlow';
    else if (url.includes('/pcas/')) result.module = 'PolicyAudit';
    else result.module = 'Unknown';

    // Get all text content
    const text = await page.evaluate(() => document.body?.innerText || '');

    // Extract endpoints using patterns
    const endpoints = new Set();
    for (const pattern of ENDPOINT_PATTERNS) {
      const matches = text.match(pattern) || [];
      for (const match of matches) {
        endpoints.add(match.trim());
      }
    }

    // Also look for curl examples
    const curlMatches = text.match(/curl\s+[^\n]+/gi) || [];
    for (const curl of curlMatches) {
      const urlMatch = curl.match(/https?:\/\/[^\s'"]+/);
      if (urlMatch) {
        const apiPath = urlMatch[0].replace(/https?:\/\/[^\/]+/, '');
        if (apiPath.startsWith('/')) {
          endpoints.add(apiPath.split('?')[0]);
        }
      }
    }

    // Look for code blocks with API paths
    const codeBlocks = await page.$$eval('pre, code, .code, .endpoint, .api-url', elements =>
      elements.map(el => el.textContent).filter(t => t && t.includes('/'))
    );
    for (const block of codeBlocks) {
      for (const pattern of ENDPOINT_PATTERNS) {
        const matches = block.match(pattern) || [];
        for (const match of matches) {
          endpoints.add(match.trim());
        }
      }
    }

    result.endpoints = [...endpoints];

    // Extract links to other docs pages
    const links = await page.$$eval('a[href]', anchors =>
      anchors.map(a => a.href).filter(href =>
        href.includes('docs.qualys.com') &&
        href.endsWith('.htm') &&
        !href.includes('#') &&
        !href.includes('javascript:')
      )
    );
    result.links = [...new Set(links)];

  } catch (e) {
    result.error = e.message.substring(0, 200);
  }

  return result;
}

async function crawl() {
  console.log('Starting Qualys API docs crawler...');
  console.log(`Seed URLs: ${SEED_URLS.length}`);
  console.log(`Max pages: ${MAX_PAGES}`);
  console.log(`Output: ${OUTPUT_DIR}`);

  fs.mkdirSync(OUTPUT_DIR, { recursive: true });

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/146.0.0.0 Safari/537.36'
  });

  const visited = new Set();
  const queue = [...SEED_URLS];
  const allResults = [];
  const allEndpoints = new Map(); // endpoint -> {module, pages[]}
  let pageCount = 0;

  while (queue.length > 0 && pageCount < MAX_PAGES) {
    // Process batch
    const batch = [];
    while (batch.length < CONCURRENCY && queue.length > 0) {
      const url = queue.shift();
      if (!visited.has(url)) {
        visited.add(url);
        batch.push(url);
      }
    }

    if (batch.length === 0) continue;

    const promises = batch.map(async (url) => {
      const page = await context.newPage();
      try {
        const result = await extractFromPage(page, url);
        return result;
      } finally {
        await page.close();
      }
    });

    const results = await Promise.all(promises);

    for (const result of results) {
      pageCount++;
      allResults.push(result);

      // Track endpoints
      for (const ep of result.endpoints) {
        if (!allEndpoints.has(ep)) {
          allEndpoints.set(ep, { module: result.module, pages: [] });
        }
        allEndpoints.get(ep).pages.push(result.url);
      }

      // Add discovered links to queue
      for (const link of result.links) {
        if (!visited.has(link) && !queue.includes(link)) {
          queue.push(link);
        }
      }

      const epCount = result.endpoints.length;
      const linkCount = result.links.length;
      if (epCount > 0) {
        console.log(`[${pageCount}] ${result.module}: ${epCount} endpoints, ${linkCount} links — ${result.url.split('/').slice(-2).join('/')}`);
      } else if (pageCount % 50 === 0) {
        console.log(`[${pageCount}] ${result.module}: (no endpoints) — ${result.url.split('/').slice(-2).join('/')}`);
      }
    }
  }

  // Save results
  const endpointList = [];
  for (const [endpoint, info] of allEndpoints) {
    endpointList.push({
      endpoint,
      module: info.module,
      pageCount: info.pages.length,
      pages: info.pages.slice(0, 3),
    });
  }
  endpointList.sort((a, b) => a.module.localeCompare(b.module) || a.endpoint.localeCompare(b.endpoint));

  const summary = {
    crawledAt: new Date().toISOString(),
    pagesVisited: pageCount,
    uniqueEndpoints: endpointList.length,
    byModule: {},
  };

  for (const ep of endpointList) {
    if (!summary.byModule[ep.module]) {
      summary.byModule[ep.module] = { count: 0, endpoints: [] };
    }
    summary.byModule[ep.module].count++;
    summary.byModule[ep.module].endpoints.push(ep.endpoint);
  }

  fs.writeFileSync(
    path.join(OUTPUT_DIR, 'endpoints.json'),
    JSON.stringify(endpointList, null, 2)
  );
  fs.writeFileSync(
    path.join(OUTPUT_DIR, 'summary.json'),
    JSON.stringify(summary, null, 2)
  );
  fs.writeFileSync(
    path.join(OUTPUT_DIR, 'pages.json'),
    JSON.stringify(allResults.map(r => ({
      url: r.url,
      title: r.title,
      module: r.module,
      endpointCount: r.endpoints.length,
      linkCount: r.links.length,
      error: r.error,
    })), null, 2)
  );

  console.log(`\n${'='.repeat(60)}`);
  console.log(`CRAWL COMPLETE`);
  console.log(`${'='.repeat(60)}`);
  console.log(`Pages visited: ${pageCount}`);
  console.log(`Unique endpoints: ${endpointList.length}`);
  console.log(`\nBy module:`);
  for (const [mod, data] of Object.entries(summary.byModule).sort((a, b) => b[1].count - a[1].count)) {
    console.log(`  ${mod}: ${data.count} endpoints`);
  }

  await browser.close();
  return summary;
}

crawl().catch(console.error);
