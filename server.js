// server.js - Main server file for Realify fake news detection API
import dotenv from "dotenv";
import express from "express";

import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import bodyParser from 'body-parser';
import path from 'path';
import axios from 'axios';
import natural from 'natural';

const { TfIdf } = natural;

// Initialize express app
const app = express();
dotenv.config();

const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(cookieParser());

app.use(express.static(path.join(__dirname, 'public')));

// Initialize text processing tools
const tokenizer = new natural.WordTokenizer();
const stopwords = ['a', 'about', 'above', 'after', 'again', 'against', 'all', 'am', 'an', 'and', 'any', 'are', 'as', 'at', 'be', 'because', 'been', 'before', 'being', 'below', 'between', 'both', 'but', 'by', 'could', 'did', 'do', 'does', 'doing', 'down', 'during', 'each', 'few', 'for', 'from', 'further', 'had', 'has', 'have', 'having', 'he', 'her', 'here', 'hers', 'herself', 'him', 'himself', 'his', 'how', 'i', 'if', 'in', 'into', 'is', 'it', 'its', 'itself', 'just', 'me', 'more', 'most', 'my', 'myself', 'no', 'nor', 'not', 'now', 'of', 'off', 'on', 'once', 'only', 'or', 'other', 'our', 'ours', 'ourselves', 'out', 'over', 'own', 'same', 'she', 'should', 'so', 'some', 'such', 'than', 'that', 'the', 'their', 'theirs', 'them', 'themselves', 'then', 'there', 'these', 'they', 'this', 'those', 'through', 'to', 'too', 'under', 'until', 'up', 'very', 'was', 'we', 'were', 'what', 'when', 'where', 'which', 'while', 'who', 'whom', 'why', 'will', 'with', 'would', 'you', 'your', 'yours', 'yourself', 'yourselves'];

// Database of known fake news keywords and phrases (simplified for demo)
const fakeNewsIndicators = [
    'shocking truth', 'they don\'t want you to know', 'mainstream media won\'t tell you',
    'secret cure', 'doctors hate this', 'conspiracy', 'cover-up', 'illuminati',
    'government doesn\'t want you to know', 'miracle cure', 'hidden agenda'
];

// Database of credible sources (simplified for demo)
const credibleDomains = [
    'bbc.com', 'bbc.co.uk', 'reuters.com', 'apnews.com', 'npr.org', 
    'nytimes.com', 'washingtonpost.com', 'wsj.com', 'economist.com',
    'nature.com', 'science.org', 'time.com', 'theguardian.com'
];

// API endpoint for article verification
app.post('/api/verify', async (req, res) => {
    try {
        const { url, text } = req.body;
        
        // Get article content either from URL or provided text
        let articleContent = '';
        let source = 'unknown';
        
        if (url) {
            try {
                // Extract domain for source credibility check
                const urlObj = new URL(url);
                source = urlObj.hostname;
                
                // Fetch article content from URL (in a real app, use proper article extraction)
                const response = await axios.get(url);
                articleContent = extractTextFromHTML(response.data);
            } catch (error) {
                console.error('Error fetching URL:', error);
                return res.status(400).json({ error: 'Could not fetch article from the provided URL' });
            }
        } else if (text) {
            // Use provided text directly
            articleContent = text;
        } else {
            return res.status(400).json({ error: 'Please provide either a URL or article text' });
        }
        
        // Analyze the article
        const analysisResult = analyzeArticle(articleContent, source);
        
        // Return the analysis
        res.json(analysisResult);
        
    } catch (error) {
        console.error('Error processing verification request:', error);
        res.status(500).json({ error: 'An error occurred while analyzing the article' });
    }
});

// Function to analyze article content
function analyzeArticle(content, source) {
    // DISCLAIMER: This is a simplified demo algorithm. 
    // A real fake news detection system would use advanced NLP and ML techniques.
    
    // 1. Calculate source credibility score
    const sourceCredibilityScore = calculateSourceCredibility(source);
    
    // 2. Calculate content analysis score
    const contentAnalysisScore = analyzeContent(content);
    
    // 3. Calculate sensationalism score
    const sensationalismScore = analyzeSensationalism(content);
    
    // 4. Calculate final credibility score (weighted average)
    const credibilityScore = Math.round(
        (sourceCredibilityScore * 0.3) + 
        (contentAnalysisScore * 0.5) + 
        (sensationalismScore * 0.2)
    );
    
    // Generate summary and recommendation based on score
    let summary = '';
    let recommendation = '';
    
    if (credibilityScore >= 80) {
        summary = 'This article appears to be from a credible source and contains balanced reporting.';
        recommendation = 'This content is likely reliable and can be shared.';
    } else if (credibilityScore >= 50) {
        summary = 'This article contains some questionable elements but may have some accurate information.';
        recommendation = 'Exercise caution and cross-check with other sources before sharing.';
    } else {
        summary = 'This article contains many red flags associated with misinformation.';
        recommendation = 'This content is likely unreliable and should not be shared without extensive verification.';
    }
    
    // Prepare analysis factors to display to user
    const factors = [
        {
            name: 'Source Credibility',
            score: sourceCredibilityScore,
            description: `The source ${source} has a credibility score of ${sourceCredibilityScore}/100.`
        },
        {
            name: 'Content Analysis',
            score: contentAnalysisScore,
            description: `Content analysis revealed a reliability score of ${contentAnalysisScore}/100.`
        },
        {
            name: 'Sensationalism Detection',
            score: sensationalismScore,
            description: `The article has a sensationalism score of ${100 - sensationalismScore}/100 (lower is better).`
        }
    ];
    
    // Return the complete analysis
    return {
        credibilityScore,
        summary,
        recommendation,
        factors
    };
}

// Function to calculate source credibility
function calculateSourceCredibility(source) {
    // Check if source is in the list of credible domains
    for (const domain of credibleDomains) {
        if (source.includes(domain)) {
            return 95; // High credibility score for known reliable sources
        }
    }
    
    // Check for other indicators of credibility
    if (source.includes('edu')) {
        return 85; // Educational institutions
    } else if (source.includes('gov')) {
        return 90; // Government websites
    } else if (source.includes('org')) {
        return 75; // Non-profit organizations (may vary in credibility)
    } else if (source === 'unknown') {
        return 30; // Unknown sources are treated with high skepticism
    } else {
        // Generic score for other domains
        return 50; // Neutral starting point
    }
}

// Function to analyze content reliability
function analyzeContent(content) {
    const tokens = tokenizer.tokenize(content.toLowerCase());
    const filteredTokens = tokens.filter(token => !stopwords.includes(token));
    
    // Count fake news indicators
    let fakeNewsMatches = 0;
    for (const indicator of fakeNewsIndicators) {
        if (content.toLowerCase().includes(indicator.toLowerCase())) {
            fakeNewsMatches++;
        }
    }
    
    // Calculate TF-IDF for content analysis
    const tfidf = new TfIdf();
    tfidf.addDocument(filteredTokens.join(' '));
    
    // Check for lack of evidence/citations
    const hasCitations = content.includes('according to') || 
                        content.includes('study shows') || 
                        content.includes('research') ||
                        content.includes('data from');
    
    // Check for balanced reporting
    const hasMultiplePerspectives = content.includes('however') || 
                                  content.includes('on the other hand') || 
                                  content.includes('critics say') ||
                                  content.includes('others argue');
    
    // Calculate content score based on above factors
    let contentScore = 70; // Start with a neutral-positive score
    
    // Deduct points for fake news indicators
    contentScore -= (fakeNewsMatches * 10);
    
    // Add points for citations
    if (hasCitations) contentScore += 15;
    
    // Add points for balanced reporting
    if (hasMultiplePerspectives) contentScore += 15;
    
    // Ensure score stays within 0-100 range
    return Math.max(0, Math.min(100, contentScore));
}

// Function to analyze sensationalism
function analyzeSensationalism(content) {
    // Check for all caps words (shouting)
    const allCapsRegex = /\b[A-Z]{4,}\b/g;
    const allCapsMatches = (content.match(allCapsRegex) || []).length;
    
    // Check for excessive punctuation
    const excessivePunctuationRegex = /(!{2,}|\?{2,})/g;
    const excessivePunctuationMatches = (content.match(excessivePunctuationRegex) || []).length;
    
    // Check for sensationalist words
    const sensationalistWords = [
        'shocking', 'incredible', 'mind-blowing', 'outrageous', 'unbelievable', 
        'jaw-dropping', 'amazing', 'stunning', 'blockbuster', 'bombshell'
    ];
    
    let sensationalistWordCount = 0;
    for (const word of sensationalistWords) {
        const regex = new RegExp(`\\b${word}\\b`, 'gi');
        const matches = (content.match(regex) || []).length;
        sensationalistWordCount += matches;
    }
    
    // Calculate sensationalism score
    let sensationalismScore = 100; // Higher is better (less sensationalist)
    
    // Deduct points for sensationalist elements
    sensationalismScore -= (allCapsMatches * 5);
    sensationalismScore -= (excessivePunctuationMatches * 5);
    sensationalismScore -= (sensationalistWordCount * 3);
    
    // Ensure score stays within 0-100 range
    return Math.max(0, Math.min(100, sensationalismScore));
}

// Function to extract text from HTML
function extractTextFromHTML(html) {
    // This is a simplified version; a real implementation would use a proper HTML parser
    // Strip HTML tags using regex (not ideal but works for demo)
    let text = html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, ' ');
    text = text.replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, ' ');
    text = text.replace(/<[^>]+>/g, ' ');
    
    // Normalize whitespace
    text = text.replace(/\s+/g, ' ').trim();
    
    return text;
}

// Start the server
app.listen(PORT, () => {
    console.log(`Realify API server running on port ${PORT}`);
});

// Add a simple health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'UP', message: 'Server is running properly' });
});

// Add a simple home route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/realify', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true
}).then(() => {
  console.log('MongoDB connected successfully');
}).catch(err => {
  console.error('MongoDB connection error:', err);
});

// User model - create models/User.js file
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  verificationHistory: [{
    articleUrl: String,
    articleText: String,
    credibilityScore: Number,
    verifiedAt: {
      type: Date,
      default: Date.now
    }
  }]
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare passwords
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Create User model
const User = mongoose.model('User', userSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-for-development-only';
const JWT_EXPIRE = '24h';

// Authentication middleware
const auth = async (req, res, next) => {
  try {
    const token = req.cookies.token || req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid authentication token' });
  }
};

// Authentication routes
app.post('/api/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Check if user already exists
    let existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already in use' });
    }
    
    existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already taken' });
    }
    
    // Create new user
    const user = new User({
      username,
      email,
      password
    });
    
    await user.save();
    
    // Generate JWT token
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: JWT_EXPIRE });
    
    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      secure: process.env.NODE_ENV === 'production'
    });
    
    res.status(201).json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Server error during signup' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate JWT token
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: JWT_EXPIRE });
    
    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      secure: process.env.NODE_ENV === 'production'
    });
    
    res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true, message: 'Logged out successfully' });
});

app.get('/api/profile', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    res.json({ success: true, user });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Server error fetching profile' });
  }
});

// Modify verify endpoint to save history for logged-in users
app.post('/api/verify', async (req, res) => {
  try {
    const { url, text } = req.body;
    
    // Get article content either from URL or provided text
    let articleContent = '';
    let source = 'unknown';
    
    if (url) {
      try {
        // Extract domain for source credibility check
        const urlObj = new URL(url);
        source = urlObj.hostname;
        
        // Fetch article content from URL (in a real app, use proper article extraction)
        const response = await axios.get(url);
        articleContent = extractTextFromHTML(response.data);
      } catch (error) {
        console.error('Error fetching URL:', error);
        return res.status(400).json({ error: 'Could not fetch article from the provided URL' });
      }
    } else if (text) {
      // Use provided text directly
      articleContent = text;
    } else {
      return res.status(400).json({ error: 'Please provide either a URL or article text' });
    }
    
    // Analyze the article
    const analysisResult = analyzeArticle(articleContent, source);
    
    // Save verification history if user is logged in
    if (req.user) {
      await User.findByIdAndUpdate(req.user._id, {
        $push: {
          verificationHistory: {
            articleUrl: url || '',
            articleText: text || '',
            credibilityScore: analysisResult.credibilityScore
          }
        }
      });
    }
    
    // Return the analysis
    res.json(analysisResult);
    
  } catch (error) {
    console.error('Error processing verification request:', error);
    res.status(500).json({ error: 'An error occurred while analyzing the article' });
  }
});
module.exports = app; // Export for testing