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

## Installation

### Prerequisites
- Node.js (v16 or higher)
- MongoDB (v4.4 or higher)
- npm or yarn package manager

### Setup Instructions

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd rotaract-club-website
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Environment Configuration**
   ```bash
   cp .env.example .env
   # Edit .env file with your configuration
   ```

4. **Database Setup**
   ```bash
   # Make sure MongoDB is running
   # The application will create the database automatically
   ```

5. **Create Upload Directories**
   ```bash
   mkdir -p uploads/events uploads/profiles
   ```

6. **Start the Application**
   ```bash
   # Development mode
   npm run dev
   
   # Production mode
   npm start
   ```

7. **Access the Application**
   - Open your browser and navigate to `http://localhost:3000`
   - The application will be running with sample data

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_ENV` | Environment mode | `development` |
| `PORT` | Server port | `3000` |
| `MONGODB_URI` | MongoDB connection string | `mongodb://localhost:27017/rotaract_club` |
| `JWT_SECRET` | JWT signing secret | Required |
| `SESSION_SECRET` | Session signing secret | Required |

### Database Configuration

The application uses MongoDB with the following collections:
- `users`: User accounts and profiles
- `events`: Event information and registrations
- `donations`: Donation records and tracking
- `announcements`: Club announcements
- `contacts`: Contact form submissions

## API Documentation

### Authentication Endpoints
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/auth/me` - Get current user
- `PUT /api/auth/change-password` - Change password

### Event Endpoints
- `GET /api/events` - Get all events
- `GET /api/events/:id` - Get single event
- `POST /api/events` - Create event (BOD/Admin)
- `PUT /api/events/:id` - Update event
- `POST /api/events/:id/register` - Register for event

### User Management Endpoints
- `GET /api/members` - Get all members
- `GET /api/members/:id` - Get member profile
- `PUT /api/members/:id` - Update member profile
- `PUT /api/members/:id/status` - Update member status

### Admin Endpoints
- `GET /api/admin/dashboard` - Admin dashboard data
- `GET /api/admin/users` - User management
- `GET /api/admin/reports` - Generate reports

## User Roles & Permissions

### Member
- View public events and announcements
- Register for events
- Update own profile
- Participate in discussions

### Core Team
- All member permissions
- Manage event logistics
- Update event statuses
- Manage media content
- View member list

### Board of Directors (BOD)
- All core team permissions
- Manage members (approve/reject)
- Approve events
- Review donations
- Create announcements
- Access reports

### Admin
- All BOD permissions
- Full user management
- System configuration
- Advanced analytics
- Database management

## Security Features

### Authentication Security
- Password complexity requirements
- Account lockout after failed attempts
- JWT token expiration and refresh
- Secure session management

### Data Protection
- Input validation and sanitization
- SQL injection prevention
- XSS protection
- CSRF protection
- Rate limiting

### File Upload Security
- File type validation
- File size limits
- Secure file storage
- Malware scanning ready

## Deployment

### Production Deployment

1. **Environment Setup**
   ```bash
   NODE_ENV=production
   # Set all required environment variables
   ```

2. **Database Setup**
   ```bash
   # Use MongoDB Atlas or dedicated MongoDB server
   # Set MONGODB_URI to production database
   ```

3. **Security Configuration**
   ```bash
   # Generate strong secrets
   # Configure HTTPS
   # Set up reverse proxy (nginx)
   ```

4. **Process Management**
   ```bash
   # Use PM2 for process management
   npm install -g pm2
   pm2 start server.js --name rotaract-club
   ```

### Docker Deployment

```dockerfile
# Dockerfile included for containerized deployment
docker build -t rotaract-club .
docker run -p 3000:3000 rotaract-club
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Code Style
- Use ESLint configuration
- Follow Node.js best practices
- Write meaningful commit messages
- Add comments for complex logic

## Testing

```bash
# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Run linting
npm run lint
```

## Monitoring & Maintenance

### Health Checks
- Database connection monitoring
- API endpoint health checks
- File system monitoring
- Memory and CPU usage tracking

### Logging
- Application logs with Winston
- Error tracking and reporting
- User activity logging
- Performance monitoring

### Backup Strategy
- Regular database backups
- File upload backups
- Configuration backups
- Disaster recovery plan

## Support

For support and questions:
- Create an issue in the repository
- Contact the development team
- Check the documentation wiki

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Rotary International for the Rotaract program
- Bootstrap and TailwindCSS teams
- MongoDB and Express.js communities
- All contributors and testers

---

**Built with ❤️ for Rotaract Clubs worldwide**
