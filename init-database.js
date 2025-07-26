const mongoose = require('mongoose');
require('dotenv').config();

// Import all models to ensure they are registered
const User = require('./models/User');
const Event = require('./models/Event');
const Donation = require('./models/Donation');
const Announcement = require('./models/Announcement');
const Contact = require('./models/Contact');

const initializeDatabase = async () => {
    try {
        // Connect to MongoDB
        console.log('🔌 Connecting to MongoDB...');
        await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/rtr2', {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        console.log('✅ MongoDB Connected Successfully');
        console.log(`📊 Database: ${mongoose.connection.name}`);

        // Check if collections exist and create indexes
        console.log('\n🔧 Initializing collections and indexes...');

        // Initialize User collection
        try {
            await User.createIndexes();
            console.log('✅ User collection initialized');
        } catch (error) {
            console.log('⚠️  User collection already exists');
        }

        // Initialize Event collection
        try {
            await Event.createIndexes();
            console.log('✅ Event collection initialized');
        } catch (error) {
            console.log('⚠️  Event collection already exists');
        }

        // Initialize Donation collection
        try {
            await Donation.createIndexes();
            console.log('✅ Donation collection initialized');
        } catch (error) {
            console.log('⚠️  Donation collection already exists');
        }

        // Initialize Announcement collection
        try {
            await Announcement.createIndexes();
            console.log('✅ Announcement collection initialized');
        } catch (error) {
            console.log('⚠️  Announcement collection already exists');
        }

        // Initialize Contact collection
        try {
            await Contact.createIndexes();
            console.log('✅ Contact collection initialized');
        } catch (error) {
            console.log('⚠️  Contact collection already exists');
        }

        // Create sample admin user if no users exist
        const userCount = await User.countDocuments();
        if (userCount === 0) {
            console.log('\n👤 Creating default admin user...');
            const bcrypt = require('bcryptjs');
            
            const adminUser = new User({
                firstName: 'Admin',
                lastName: 'User',
                email: 'admin@rotaract.com',
                password: await bcrypt.hash('admin123', 12),
                role: 'admin',
                status: 'active',
                phone: '+1234567890',
                dateOfBirth: new Date('1990-01-01'),
                address: {
                    street: '123 Admin Street',
                    city: 'Admin City',
                    state: 'Admin State',
                    zipCode: '12345',
                    country: 'Admin Country'
                },
                joinDate: new Date(),
                isEmailVerified: true
            });

            await adminUser.save();
            console.log('✅ Default admin user created');
            console.log('📧 Email: admin@rotaract.com');
            console.log('🔑 Password: admin123');
        }

        // Display collection statistics
        console.log('\n📊 Database Statistics:');
        const collections = await mongoose.connection.db.listCollections().toArray();
        for (const collection of collections) {
            const count = await mongoose.connection.db.collection(collection.name).countDocuments();
            console.log(`   ${collection.name}: ${count} documents`);
        }

        console.log('\n🎉 Database initialization completed successfully!');
        console.log('🚀 You can now start the server with: npm start');

    } catch (error) {
        console.error('❌ Database initialization failed:', error);
        process.exit(1);
    } finally {
        await mongoose.connection.close();
        console.log('🔌 Database connection closed');
    }
};

// Run initialization
initializeDatabase();
