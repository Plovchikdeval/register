import fs from "fs";

const ALLOWED_TYPES = [
    "A",
    "AAAA",
    "CNAME",
    "TXT",
    "URL",
    "MX",
    "SRV",
    "CAA",
    "NS",
    "DS",
    "TLSA",
];

const RESERVED_JSON_PATH = "./reserved.json";
let RESERVED_SUBDOMAINS = [];

try {
    const reservedData = fs.readFileSync(RESERVED_JSON_PATH, "utf8");
    const parsed = JSON.parse(reservedData);

    if (!Array.isArray(parsed)) {
        console.error("⚠️ Warning: reserved.json must be an array of strings. Skipping reserved check.");
    } else {
        RESERVED_SUBDOMAINS = parsed
            .filter(item => typeof item === "string")
            .map(item => item.toLowerCase().trim());
    }
} catch (err) {
    console.error("⚠️ Warning: Could not load reserved-subdomains.json. Skipping reserved check.");
}

const REQUIRED_TOP_KEYS = ["user", "subdomain", "records"];
const ALLOWED_TOP_KEYS = ["user", "description", "subdomain", "records"];

const REQUIRED_USER_KEYS = ["username"];

const ALLOWED_RECORD_KEYS = [
    "type",
    "name",
    "value",
    "proxied",
    "priority",
    "target",
    "weight",
    "port",
    "flags",
    "tag",
    "key_tag",
    "algorithm",
    "digest_type",
    "digest",
    "usage",
    "selector",
    "matching_type",
    "certificate",
];

const IPV4_REGEX =
    /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

const IPV6_REGEX =
    /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(::)|(([0-9a-fA-F]{1,4}:){1,7}:)|(:([0-9a-fA-F]{1,4}:){1,7})|(([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}))$/;

function fail(msg, exitCode = 1) {
    console.error("❌", msg);
    process.exit(exitCode);
}

const files = fs
    .readFileSync("changes.txt", "utf8")
    .split("\n")
    .filter((f) => f.trim() && f.startsWith("domains/") && f.endsWith(".json"));

if (files.length === 0) {
    process.exit(0);
}

for (const file of files) {
    let data;

    if (!fs.existsSync(file)) {
        continue;
    }

    try {
        data = JSON.parse(fs.readFileSync(file, "utf8"));
    } catch {
        fail(`${file}: invalid JSON`);
    }

    for (const key of Object.keys(data)) {
        if (!ALLOWED_TOP_KEYS.includes(key)) {
            fail(`${file}: extra top-level key "${key}"`);
        }
    }
    for (const key of REQUIRED_TOP_KEYS) {
        if (!(key in data)) {
            fail(`${file}: missing required key "${key}"`);
        }
    }

    if (typeof data.user !== "object" || data.user === null) {
        fail(`${file}: user must be an object`);
    }
    for (const key of REQUIRED_USER_KEYS) {
        if (!data.user[key]) {
            fail(`${file}: user.${key} is required`);
        }
    }

    if (!/^[a-z0-9-]+$/.test(data.subdomain)) {
        fail(`${file}: invalid subdomain format`);
    }

    const subdomainLower = data.subdomain.toLowerCase();
    if (RESERVED_SUBDOMAINS.includes(subdomainLower)) {
        fail(
            `${file}: the subdomain "${data.subdomain}" is reserved and cannot be registered`,
            5
        );
    }

    const expectedFile = `domains/${data.subdomain}.json`;
    if (file !== expectedFile) {
        fail(`${file}: filename must match subdomain (${expectedFile})`);
    }

    if (!Array.isArray(data.records)) {
        fail(`${file}: records must be an array`);
    }
    if (data.records.length === 0) {
        fail(`${file}: at least one DNS record is required`);
    }

    let hasNS = false;
    let hasDS = false;

    for (const r of data.records) {
        if (typeof r !== "object" || r === null) {
            fail(`${file}: record must be an object`);
        }

        const type = String(r.type).toUpperCase();

        if ("proxied" in r) {
            if (typeof r.proxied !== "boolean") fail(`${file}: 'proxied' must be a boolean`);
            if (!["A", "AAAA", "CNAME"].includes(type)) {
                fail(`${file}: 'proxied' is only allowed for A, AAAA, and CNAME records`);
            }
        }

        if (type === "NS" || type === "DS") {
            if (r.name !== data.subdomain) {
                fail(`${file}: ${type} records must be set on the subdomain exactly, not a child`);
            }
        }

        for (const key of Object.keys(r)) {
            if (!ALLOWED_RECORD_KEYS.includes(key)) {
                fail(`${file}: invalid record key "${key}"`);
            }
        }

        if (!ALLOWED_TYPES.includes(type)) {
            fail(`${file}: unsupported record type "${r.type}"`);
        }

        if (typeof r.name !== "string") {
            fail(`${file}: record name must be a string`);
        }
        if (r.name.includes("*")) {
            fail(`${file}: wildcard records are not allowed`);
        }
        if (
            r.name !== data.subdomain &&
            !r.name.endsWith(`.${data.subdomain}`)
        ) {
            fail(`${file}: record outside assigned subdomain`);
        }

        if (type === "A") {
            if (typeof r.value !== "string" || !IPV4_REGEX.test(r.value)) {
                fail(`${file}: invalid IPv4 address`);
            }
        }
        else if (type === "AAAA") {
            if (typeof r.value !== "string" || !IPV6_REGEX.test(r.value)) {
                fail(`${file}: invalid IPv6 address`);
            }
        }
        else if (["CNAME", "TXT", "URL", "NS"].includes(type)) {
            if (typeof r.value !== "string") {
                fail(`${file}: ${type} record requires string 'value'`);
            }
        }
        else if (type === "MX") {
            if (typeof r.target !== "string") fail(`${file}: MX requires 'target'`);
            if (typeof r.priority !== "number" || r.priority < 0) fail(`${file}: MX priority must be >= 0`);
        }
        else if (type === "SRV") {
            if (typeof r.priority !== "number" || r.priority < 0) fail(`${file}: SRV priority must be >= 0`);
            if (typeof r.weight !== "number" || r.weight < 0) fail(`${file}: SRV weight must be >= 0`);
            if (typeof r.port !== "number" || r.port <= 0) fail(`${file}: SRV port must be > 0`);
            if (typeof r.target !== "string") fail(`${file}: SRV requires 'target'`);
        }
        else if (type === "CAA") {
            if (typeof r.flags !== "number") fail(`${file}: CAA requires numeric 'flags'`);
            if (typeof r.tag !== "string") fail(`${file}: CAA requires string 'tag'`);
            if (typeof r.value !== "string") fail(`${file}: CAA requires string 'value'`);
        }
        else if (type === "DS") {
            if (typeof r.key_tag !== "number") fail(`${file}: DS requires numeric 'key_tag'`);
            if (typeof r.algorithm !== "number") fail(`${file}: DS requires numeric 'algorithm'`);
            if (typeof r.digest_type !== "number") fail(`${file}: DS requires numeric 'digest_type'`);
            if (typeof r.digest !== "string") fail(`${file}: DS requires string 'digest'`);
            hasDS = true;
        }
        else if (type === "TLSA") {
            if (typeof r.usage !== "number") fail(`${file}: TLSA requires numeric 'usage'`);
            if (typeof r.selector !== "number") fail(`${file}: TLSA requires numeric 'selector'`);
            if (typeof r.matching_type !== "number") fail(`${file}: TLSA requires numeric 'matching_type'`);
            if (typeof r.certificate !== "string") fail(`${file}: TLSA requires string 'certificate'`);
        }

        if (type === "NS") hasNS = true;
    }

    if (hasDS && !hasNS) {
        fail(`${file}: DS records are useless without NS records.`);
    }
}

console.log("✅ DNS JSON validation passed");