# Rotaract Club Website

A complete, production-ready website for Rotaract Clubs with role-based access control, event management, donation tracking, and comprehensive admin features.

## Features

### 🌟 Frontend Features
- **Responsive Design**: Bootstrap + TailwindCSS for modern, mobile-first design
- **Interactive UI**: Smooth animations, elegant modals, and loading states
- **Accessibility**: WCAG compliant with proper ARIA labels and keyboard navigation
- **SEO Optimized**: Meta tags, structured data, and semantic HTML

### 🔐 Authentication & Authorization
- **Multi-Role System**: Member, Core Team, BOD, and Admin roles
- **Secure Authentication**: JWT tokens with refresh mechanism
- **Session Management**: Express sessions with MongoDB store
- **Password Security**: Bcrypt hashing with salt rounds
- **Account Security**: Login attempt limiting and account locking

### 👥 User Management
- **Member Applications**: Public registration with approval workflow
- **Profile Management**: Comprehensive user profiles with image uploads
- **Role-Based Dashboards**: Customized dashboards for each user role
- **User Analytics**: Registration trends and activity tracking

### 📅 Event Management
- **Event Creation**: Rich event creation with images and documents
- **Registration System**: Event registration with capacity limits
- **Event Categories**: Community service, fundraising, social, etc.
- **Event Analytics**: Attendance tracking and feedback collection
- **Recurring Events**: Support for recurring event patterns

### 💰 Donation Management
- **Multiple Donation Types**: Monetary, in-kind, and service donations
- **Payment Integration**: Ready for Stripe/PayPal integration
- **Receipt Generation**: Automated receipt generation and tracking
- **Donor Management**: Comprehensive donor profiles and history
- **Campaign Tracking**: Link donations to specific campaigns

### 📢 Communication System
- **Announcements**: Targeted announcements with scheduling
- **Contact Management**: Advanced contact form with CRM features
- **Email Integration**: Ready for email service integration
- **Notification System**: Multi-channel notification support

### 📊 Admin Panel
- **Comprehensive Dashboard**: Real-time statistics and analytics
- **User Management**: Full CRUD operations for users
- **Content Management**: Manage events, announcements, and donations
- **Reporting System**: Generate detailed reports and analytics
- **System Health**: Monitor application performance and health

## Technology Stack

### Backend
- **Node.js**: Runtime environment
- **Express.js**: Web application framework
- **MongoDB**: Database with Mongoose ODM
- **JWT**: Authentication tokens
- **Bcrypt**: Password hashing
- **Multer**: File upload handling
- **Express Validator**: Input validation
- **Helmet**: Security middleware

### Frontend
- **EJS**: Server-side templating
- **Bootstrap 5**: CSS framework
- **TailwindCSS**: Utility-first CSS
- **Font Awesome**: Icon library
- **Vanilla JavaScript**: Client-side functionality

### Security
- **Rate Limiting**: Prevent abuse and DDoS
- **CORS**: Cross-origin resource sharing
- **Helmet**: Security headers
- **Input Validation**: Comprehensive validation
- **SQL Injection Prevention**: Mongoose protection
- **XSS Protection**: Content Security Policy

---

**Built with ❤️ for Rotaract Clubs worldwide**
