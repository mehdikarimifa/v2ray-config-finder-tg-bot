export const logger = {
    info: (msg, context = 'System') => {
        console.log(`[${new Date().toISOString()}] [INFO] [${context}] ${msg}`);
    },
    warn: (msg, context = 'System') => {
        console.warn(`[${new Date().toISOString()}] [WARN] [${context}] ${msg}`);
    },
    error: (msg, error, context = 'System') => {
        console.error(`[${new Date().toISOString()}] [ERROR] [${context}] ${msg}`, error || '');
    },
    success: (msg, context = 'System') => {
        console.log(`[${new Date().toISOString()}] [✅ SUCCESS] [${context}] ${msg}`);
    }
};
