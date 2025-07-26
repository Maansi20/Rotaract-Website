const http = require('http');

console.log('🧪 Testing Server Routes...\n');

function testRoute(path, description) {
    return new Promise((resolve) => {
        const options = {
            hostname: 'localhost',
            port: 3000,
            path: path,
            method: 'GET'
        };

        const req = http.request(options, (res) => {
            console.log(`${description}: ${res.statusCode} ${res.statusMessage}`);
            
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });
            
            res.on('end', () => {
                if (res.statusCode === 200) {
                    console.log(`✅ ${description} - SUCCESS`);
                    if (path === '/donate' && data.includes('Make a Donation')) {
                        console.log('✅ Donate page content verified');
                    }
                } else {
                    console.log(`❌ ${description} - FAILED`);
                }
                resolve(res.statusCode);
            });
        });

        req.on('error', (err) => {
            console.error(`❌ ${description} - ERROR:`, err.message);
            resolve(0);
        });

        req.setTimeout(5000, () => {
            console.log(`⏰ ${description} - TIMEOUT`);
            req.destroy();
            resolve(0);
        });

        req.end();
    });
}

async function runTests() {
    console.log('Testing all routes...\n');
    
    await testRoute('/', 'Homepage');
    await testRoute('/donate', 'Donate Page');
    await testRoute('/about', 'About Page');
    await testRoute('/events', 'Events Page');
    await testRoute('/contact', 'Contact Page');
    
    console.log('\n🎉 Route testing completed!');
    process.exit(0);
}

runTests();
