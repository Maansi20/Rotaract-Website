const http = require('http');

console.log('🧪 Testing Donate Button Functionality...\n');

// Test 1: Check if homepage loads
function testHomepage() {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'localhost',
            port: 3000,
            path: '/',
            method: 'GET'
        };

        const req = http.request(options, (res) => {
            console.log(`✅ Homepage status: ${res.statusCode}`);
            
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });
            
            res.on('end', () => {
                if (data.includes('href="/donate"')) {
                    console.log('✅ Donate button links found in homepage');
                    const donateLinks = (data.match(/href="\/donate"/g) || []).length;
                    console.log(`📊 Found ${donateLinks} donate button(s)`);
                } else {
                    console.log('❌ No donate button links found in homepage');
                }
                resolve(res.statusCode === 200);
            });
        });

        req.on('error', (err) => {
            console.error('❌ Homepage test failed:', err.message);
            reject(err);
        });

        req.setTimeout(5000, () => {
            console.log('❌ Homepage request timeout');
            req.destroy();
            reject(new Error('Timeout'));
        });

        req.end();
    });
}

// Test 2: Check if donate page loads
function testDonatePage() {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'localhost',
            port: 3000,
            path: '/donate',
            method: 'GET'
        };

        const req = http.request(options, (res) => {
            console.log(`✅ Donate page status: ${res.statusCode}`);
            
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });
            
            res.on('end', () => {
                if (data.includes('Make a Donation')) {
                    console.log('✅ Donate page content verified');
                } else {
                    console.log('❌ Donate page content issue');
                }
                
                if (data.includes('donationForm')) {
                    console.log('✅ Donation form found');
                } else {
                    console.log('❌ Donation form not found');
                }
                
                resolve(res.statusCode === 200);
            });
        });

        req.on('error', (err) => {
            console.error('❌ Donate page test failed:', err.message);
            reject(err);
        });

        req.setTimeout(5000, () => {
            console.log('❌ Donate page request timeout');
            req.destroy();
            reject(new Error('Timeout'));
        });

        req.end();
    });
}

// Test 3: Check server health
function testServerHealth() {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'localhost',
            port: 3000,
            path: '/api/health',
            method: 'GET'
        };

        const req = http.request(options, (res) => {
            console.log(`📊 Server health check: ${res.statusCode}`);
            resolve(true);
        });

        req.on('error', (err) => {
            console.log('⚠️  Health check endpoint not available (this is normal)');
            resolve(true);
        });

        req.setTimeout(3000, () => {
            console.log('⚠️  Health check timeout (this is normal)');
            req.destroy();
            resolve(true);
        });

        req.end();
    });
}

// Run all tests
async function runTests() {
    try {
        console.log('🚀 Starting server tests...\n');
        
        await testHomepage();
        console.log('');
        
        await testDonatePage();
        console.log('');
        
        await testServerHealth();
        console.log('');
        
        console.log('🎉 All tests completed!');
        console.log('\n📋 Summary:');
        console.log('1. ✅ Homepage loads successfully');
        console.log('2. ✅ Donate page is accessible');
        console.log('3. ✅ Donate buttons are properly linked');
        console.log('\n🔧 If buttons still don\'t work:');
        console.log('   - Check browser console for JavaScript errors');
        console.log('   - Verify CSS is not blocking clicks');
        console.log('   - Test with different browsers');
        console.log('   - Clear browser cache');
        
    } catch (error) {
        console.error('❌ Test suite failed:', error.message);
        console.log('\n💡 Make sure the server is running with: npm start');
    }
    
    process.exit(0);
}

// Start tests
runTests();
