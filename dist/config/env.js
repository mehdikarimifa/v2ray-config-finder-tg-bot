import 'dotenv/config';
// Validation
const required = (key) => {
    const value = process.env[key];
    if (!value) {
        throw new Error(`❌ FATAL: Missing required environment variable: ${key}`);
    }
    return value;
};
export const env = {
    BOT_TOKEN: required('BOT_TOKEN'),
    ADMIN_USER_ID: parseInt(required('ADMIN_USER_ID'), 10),
    TARGET_CHANNEL_ID: required('TARGET_CHANNEL_ID'),
    XRAY_BIN: process.env.XRAY_BIN || './xray',
    TEST_INTERVAL_MINUTES: parseInt(process.env.TEST_INTERVAL_MINUTES || '30', 10),
    CONCURRENT_TESTS: parseInt(process.env.CONCURRENT_TESTS || '10', 10),
    MAX_LATENCY_MS: parseInt(process.env.MAX_LATENCY_MS || '1500', 10),
    ENABLE_SPEED_TEST: process.env.ENABLE_SPEED_TEST === 'true',
    SPEED_TEST_URL: process.env.SPEED_TEST_URL || 'http://cachefly.cachefly.net/5mb.test',
    SPEED_TEST_FILE_SIZE_MB: parseInt(process.env.SPEED_TEST_FILE_SIZE_MB || '5', 10),
    DB_PATH: process.env.DB_PATH || './v2ray_bot.sqlite',
    PROXY_URL: process.env.PROXY_URL || undefined,
};
