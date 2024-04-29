import { HttpInput, SDK, Data, RequestSpec } from "@caido/sdk-workflow";

interface ReflectedParameter {
  name: string;
  matches: Array<[number, number]>;
  context: string;
  aggressive?: string[];
  source?: string;
}

interface RequestParameter {
  key: string;
  value: string;
  source: string;
  method: string;
}

const commonAnalyticsHosts = [
  "google-analytics.com",
  "optimizely.com",
  "intercom.io",
  "hotjar.com",
  "segment.com",
  "facebook.com",
  "sentry.io",
  "doubleclick.net",
  "adservice.google.com",
  "heapanalytics.com",
  "ping.chartbeat.net",
  "scripts.kissmetrics.com",
  "optimizely.com",
  "2.rto.microsoft.com",
  "0stats.com",
  "ucs.query.yahoo.com",
  "udc.yahoo.com",
  "shavar.services.mozilla.com",
  "download.mozilla.org",
  "services.addons.mozilla.org",
  "classify-client.services.mozilla.com",
  "location.services.mozilla.com",
  "download-stats.mozilla.org",
  "firefox.settings.services.mozilla.com",
  "firefox-settings-attachments.cdn.mozilla.net",
  "detectportal.firefox.com",
  "versioncheck.addons.mozilla.org",
  "aus5.mozilla.org",
  "incoming.telemetry.mozilla.org",
  "fhr.cdn.mozilla.net",
  "analytics.tiktok.com",
  "mssdk-va.tiktok.com",
];

const commonAnalyticsEndpoints = ["/socket.io/"];

/**
 * @param {HttpInput} input
 * @param {SDK} sdk
 * @returns {MaybePromise<Data | undefined>}
 */
export async function run(
  input: HttpInput,
  sdk: SDK
): Promise<Data | undefined> {
  const { request, response } = input;

  if (!request || !response) {
    sdk.console.log("Skipping scan - request or response is missing");
    return;
  }

  const contentType = response.getHeader("Content-Type");
  if (!contentType || !contentType.toString().includes("text/html")) {
    sdk.console.log("Skipping scan - response is not HTML");
    return [];
  }

  const reqMethod = request.getMethod();
  if (reqMethod !== "GET" && reqMethod !== "POST") {
    sdk.console.log("Skipping scan - request method is not GET or POST");
    return;
  }

  for (const analytics of commonAnalyticsHosts) {
    if (request.getHost().includes(analytics)) {
      sdk.console.log("Skipping scan - common analytics URL");
      return;
    }
  }

  for (const analytics of commonAnalyticsEndpoints) {
    if (request.getPath().includes(analytics)) {
      sdk.console.log("Skipping scan - common analytics URL");
      return;
    }
  }

  sdk.console.log("=====================================");
  const reflectedParameters = await checkReflection(input, sdk);

  if (reflectedParameters.length > 0) {
    sdk.console.log(
      `Found ${reflectedParameters.length} reflected parameter(s)`
    );

    let details = "The following parameters were reflected in the response:\n";
    details += "--------\n";
    reflectedParameters.forEach((param) => {
      details += generateReport(param) + "\n";
    });

    sdk.console.log("Creating finding:");
    sdk.console.log(details);

    await sdk.findings.create({
      title: "Reflected parameters",
      reporter: "Reflector",
      request,
      description: details,
    });
  } else {
    sdk.console.log("No reflected parameters found");
  }
}

const generateReport = (reflectedParamter: ReflectedParameter) => {
  const { name, matches, context, aggressive, source } = reflectedParamter;

  let details = `${name} - reflected ${matches.length} time(s)`;

  if (context) details += ` in ${context}`;
  if (aggressive) details += ` and allows ${aggressive.join(" ")} characters`;
  if (source) details += ` (source: ${source})`;

  return details;
};

const getRequestParameters = (requestSpec: RequestSpec) => {
  const requestParameters: RequestParameter[] = [];

  const urlParams = requestSpec.getQuery().split("&");
  urlParams.forEach((param) => {
    const [key, value] = param.split("=");
    requestParameters.push({
      key,
      value,
      source: "URL",
      method: requestSpec.getMethod(),
    });
  });

  if (requestSpec.getMethod() === "POST" && requestSpec.getBody()) {
    const body = requestSpec.getBody();
    if (!body) return requestParameters;

    const contentType = requestSpec.getHeader("Content-Type");
    if (!contentType || contentType.length == 0) return requestParameters;

    if (contentType[0].includes("application/x-www-form-urlencoded")) {
      const bodyParams = body.toText().split("&");
      bodyParams.forEach((param) => {
        const [key, value] = param.split("=");
        requestParameters.push({
          key,
          value,
          source: "BODY",
          method: requestSpec.getMethod(),
        });
      });
    }
  }
  return requestParameters;
};

async function checkReflection(
  input: HttpInput,
  sdk: SDK
): Promise<ReflectedParameter[]> {
  const { request, response } = input;
  if (!request || !response) {
    sdk.console.log("Skipping scan - request or response is missing");
    return [];
  }

  sdk.console.log("Checking query parameters for reflection...");

  const requestParameters = getRequestParameters(request.toSpec());
  const reflectedParameters: ReflectedParameter[] = [];

  if (requestParameters.length === 0) {
    sdk.console.log("No query parameters found");
    return reflectedParameters;
  }

  for (const param of requestParameters) {
    sdk.console.log(`-------`);

    sdk.console.log(
      `Checking parameter "${param.key}" (source: ${param.source})`
    );

    //TODO: add support if theres no value
    if (!param.value || param.value.length === 0) {
      sdk.console.log(`Skipping parameter "${param.key}" - no value provided`);
      continue;
    }

    const matches = findMatches(response.getBody()?.toText(), param.value);
    sdk.console.log(`Found ${matches.length} reflection(s) for "${param.key}"`);

    if (matches.length > 0) {
      sdk.console.log(`Parameter "${param.key}" reflected in response`);

      const aggressiveResult = await isVulnerable(request.toSpec(), param, sdk);
      if (aggressiveResult.matches.length > 0) {
        reflectedParameters.push({
          name: param.key,
          matches: aggressiveResult.matches,
          context: aggressiveResult.context,
          aggressive: aggressiveResult.chars,
          source: param.source,
        });
      }
    }
  }

  return reflectedParameters;
}

const queryToString = (query: { [key: string]: string }) => {
  return Object.entries(query)
    .map(([name, value]) => `${name}=${value}`)
    .join("&");
};

const parseQueryString = (query: string) => {
  const params = {};
  query.split("&").forEach((param) => {
    const [name, value] = param.split("=");
    params[name] = value;
  });
  return params;
};

async function isVulnerable(
  requestSpec: RequestSpec,
  param: RequestParameter,
  sdk: SDK
) {
  const PAYLOAD = "_REFLECTION_TEST<\"'";

  if (param.source === "URL") {
    const query = parseQueryString(requestSpec.getQuery());
    query[param.key] = PAYLOAD;
    requestSpec.setQuery(queryToString(query));
  }

  if (param.source === "BODY" && requestSpec.getBody()) {
    const body = requestSpec.getBody()?.toText();
    if (!body)
      return { vulnerable: false, chars: [], context: "", matches: [] };

    const query = parseQueryString(body);
    query[param.key] = PAYLOAD;

    requestSpec.setBody(queryToString(query));
  }

  sdk.console.log(`Sending aggressive request for parameter "${param.key}"`);
  const result = await sdk.requests.send(requestSpec);
  sdk.console.log(`Received response for parameter "${param.key}"`);

  const responseBody = result.response.getBody()?.toText();
  if (!responseBody)
    return { vulnerable: false, chars: [], context: "", matches: [] };

  const matches = findMatches(responseBody, PAYLOAD);
  sdk.console.log(`${JSON.stringify(matches)} matches found for payload ${PAYLOAD}`);
  const allowedChars: string[] = [];

  if (
    matches.some(([start, end]: [number, number]) => {
      const snippet = responseBody.slice(start, end);
      return snippet.includes("<");
    })
  ) {
    allowedChars.push("<");
  }

  if (
    matches.some(([start, end]: [number, number]) => {
      const snippet = responseBody.slice(start, end);
      return snippet.includes("'");
    })
  ) {
    allowedChars.push("'");
  }

  if (
    matches.some(([start, end]: [number, number]) => {
      const snippet = responseBody.slice(start, end);
      return snippet.includes('"');
    })
  ) {
    allowedChars.push('"');
  }

  const context = getReflectionContext(matches, responseBody);

  sdk.console.log(
    `Aggressive result for "${param.key}": ${allowedChars.length}`
  );
  return {
    vulnerable: allowedChars.length > 0,
    chars: allowedChars,
    context,
    matches,
  };
}

function getReflectionContext(matches, body) {
  const CONTEXTS = {
    OUTOFTAG: "HTML",
    INTAG: "In Tag",
    INTAGQUOTE: 'In Tag Attribute (") Value',
    INTAGSINGLEQUOTE: "In Tag Attribute (') Value",
    INSCRIPT: "In Script",
    INSCRIPTQUOTE: 'In Script String (")',
    INSCRIPTSINGLEQUOTE: "In Script String (')",
  };

  for (const [start, end] of matches) {
    const tags = getTags(body);

    const tag = tags.find((tag) => tag.start < start && tag.end > end);
    if (!tag) return CONTEXTS.OUTOFTAG;

    if (tag.name === "script") {
      if (inQuotes(body, start, end, tag, '"')) {
        return CONTEXTS.INSCRIPTQUOTE;
      } else if (inQuotes(body, start, end, tag, "'")) {
        return CONTEXTS.INSCRIPTSINGLEQUOTE;
      } else {
        return CONTEXTS.INSCRIPT;
      }
    } else {
      if (inQuotes(body, start, end, tag, '"')) {
        return CONTEXTS.INTAGQUOTE;
      } else if (inQuotes(body, start, end, tag, "'")) {
        return CONTEXTS.INTAGSINGLEQUOTE;
      } else {
        return CONTEXTS.INTAG;
      }
    }
  }

  return "BODY";
}

function inQuotes(body, start, end, tag, quoteChar) {
  let inQuote = false;

  for (let i = tag.start; i < start; i++) {
    if (body[i] === quoteChar) {
      inQuote = !inQuote;
    }
  }

  if (!inQuote) return false;

  for (let i = start; i < end; i++) {
    if (body[i] === quoteChar) {
      inQuote = !inQuote;
    }
  }

  return inQuote;
}

interface Tag {
  start: number;
  end: number;
  name: string;
}

function getTags(body) {
  const tags: Tag[] = [];
  let start = 0;

  while (true) {
    start = body.indexOf("<", start);
    if (start === -1) break;

    const end = body.indexOf(">", start);
    if (end === -1) break;

    const name = body.slice(start + 1, end).split(" ")[0];
    tags.push({ start, end: end + 1, name });

    start = end + 1;
  }

  return tags;
}

function findMatches(text: string | undefined, substring: string) {
  if (!text) return [];

  const matches: Array<[number, number]> = [];
  let startIndex = 0;

  while (true) {
    const start = text.indexOf(substring, startIndex);
    if (start === -1) break;

    const end = start + substring.length;
    matches.push([start, end]);

    startIndex = end;
  }

  return matches;
}
