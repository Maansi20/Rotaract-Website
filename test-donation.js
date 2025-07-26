const express = require('express');
const mongoose = require('mongoose');
require('dotenv').config();

// Simple test to verify donation model and routes work
async function testDonation() {
    try {
        // Connect to MongoDB
        await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/rotaract_club');
        console.log('✅ MongoDB Connected');

        // Import the Donation model
        const Donation = require('./models/Donation');
        console.log('✅ Donation model loaded');

        // Test creating a donation
        const testDonation = new Donation({
            donor: {
                name: 'Test Donor',
                email: 'test@example.com',
                phone: '1234567890',
                isAnonymous: false,
                isRecurring: false
            },
            amount: 100,
            currency: 'USD',
            type: 'monetary',
            category: 'general',
            paymentMethod: 'credit-card',
            description: 'Test donation',
            status: 'completed'
        });

        await testDonation.save();
        console.log('✅ Test donation created successfully');
        console.log('Donation ID:', testDonation._id);
        console.log('Receipt Number:', testDonation.receiptNumber);

        // Test donation statistics
        const stats = await Donation.getStats();
        console.log('✅ Donation statistics:', stats);

        // Clean up test data
        await Donation.findByIdAndDelete(testDonation._id);
        console.log('✅ Test donation cleaned up');

        console.log('\n🎉 All donation functionality tests passed!');
        
    } catch (error) {
        console.error('❌ Test failed:', error.message);
    } finally {
        await mongoose.disconnect();
        console.log('✅ MongoDB disconnected');
    }
}

// Test the donation routes
function testRoutes() {
    const app = express();
    
    // Import donation routes
    try {
        const donationRoutes = require('./routes/donations');
        console.log('✅ Donation routes loaded successfully');
        
        // Test route mounting
        app.use('/api/donations', donationRoutes);
        console.log('✅ Donation routes mounted successfully');
        
        console.log('\n📋 Available donation endpoints:');
        console.log('- GET /api/donations (Admin/BOD only)');
        console.log('- GET /api/donations/stats (Admin/BOD only)');
        console.log('- GET /api/donations/top-donors (Admin/BOD only)');
        console.log('- GET /api/donations/:id');
        console.log('- POST /api/donations (Create donation)');
        console.log('- PUT /api/donations/:id/status (Admin/BOD only)');
        console.log('- POST /api/donations/:id/receipt (Admin/BOD only)');
        console.log('- POST /api/donations/:id/acknowledgment (Admin/BOD only)');
        console.log('- GET /api/donations/my/donations');
        
    } catch (error) {
        console.error('❌ Route test failed:', error.message);
    }
}

// Run tests
console.log('🧪 Testing Donation Functionality...\n');

testRoutes();
console.log('\n' + '='.repeat(50) + '\n');
testDonation();
