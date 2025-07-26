const http = require('http');

// Test if the donation page is accessible
function testDonationPage() {
    const options = {
        hostname: 'localhost',
        port: 3000,
        path: '/donate',
        method: 'GET'
    };

    const req = http.request(options, (res) => {
        console.log(`✅ Donation page status: ${res.statusCode}`);
        
        if (res.statusCode === 200) {
            console.log('🎉 Donation page is accessible!');
            console.log('📄 Content-Type:', res.headers['content-type']);
        } else {
            console.log('❌ Donation page returned error status');
        }
        
        let data = '';
        res.on('data', (chunk) => {
            data += chunk;
        });
        
        res.on('end', () => {
            if (data.includes('Make a Donation')) {
                console.log('✅ Donation page content verified - contains donation form');
            } else {
                console.log('❌ Donation page content issue - form not found');
            }
            process.exit(0);
        });
    });

    req.on('error', (err) => {
        console.error('❌ Error testing donation page:', err.message);
        console.log('💡 Make sure the server is running with: npm start');
        process.exit(1);
    });

    req.setTimeout(5000, () => {
        console.log('❌ Request timeout - server may not be running');
        req.destroy();
        process.exit(1);
    });

    req.end();
}

console.log('🧪 Testing donation page accessibility...');
testDonationPage();
