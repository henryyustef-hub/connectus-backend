const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('✅ Connected to MongoDB'))
    .catch(err => console.error('❌ MongoDB error:', err));

// ============ SCHEMAS ============

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    avatar: { type: String, default: 'U' },
    joined: { type: Date, default: Date.now },
    bio: { type: String, default: '' }
});

const PostSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    userName: { type: String, required: true },
    userAvatar: { type: String, default: 'U' },
    content: { type: String, required: true },
    image: { type: String },
    video: { type: String },
    likes: { type: Number, default: 0 },
    comments: { type: Array, default: [] },
    time: { type: Date, default: Date.now }
});

const ShopItemSchema = new mongoose.Schema({
    name: { type: String, required: true },
    price: { type: Number, required: true },
    description: { type: String, default: '' },
    image: { type: String },
    seller: { type: String, required: true },
    sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    sellerAvatar: { type: String, default: 'U' },
    comments: { type: Array, default: [] },
    shares: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});

const MessageSchema = new mongoose.Schema({
    from: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    fromName: { type: String, required: true },
    to: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    toName: { type: String, required: true },
    text: { type: String, required: true },
    time: { type: Date, default: Date.now }
});

const PhotoSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    userName: { type: String, required: true },
    data: { type: String, required: true },
    time: { type: Date, default: Date.now }
});

const VideoSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    userName: { type: String, required: true },
    data: { type: String, required: true },
    time: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Post = mongoose.model('Post', PostSchema);
const ShopItem = mongoose.model('ShopItem', ShopItemSchema);
const Message = mongoose.model('Message', MessageSchema);
const Photo = mongoose.model('Photo', PhotoSchema);
const Video = mongoose.model('Video', VideoSchema);

// ============ AUTH ENDPOINTS ============

app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'All fields required' });
        }
        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }
        const existing = await User.findOne({ email });
        if (existing) {
            return res.status(400).json({ error: 'Email already registered' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            name,
            email,
            password: hashedPassword,
            avatar: name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2)
        });
        await user.save();
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'secret_key', { expiresIn: '7d' });
        res.json({ 
            success: true, 
            user: { 
                id: user._id, 
                name, 
                email, 
                avatar: user.avatar 
            }, 
            token 
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            return res.status(400).json({ error: 'Invalid password' });
        }
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'secret_key', { expiresIn: '7d' });
        res.json({ 
            success: true, 
            user: { 
                id: user._id, 
                name: user.name, 
                email, 
                avatar: user.avatar, 
                bio: user.bio || '' 
            }, 
            token 
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/verify', async (req, res) => {
    try {
        const { token } = req.body;
        if (!token) return res.status(401).json({ error: 'No token' });
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret_key');
        const user = await User.findById(decoded.userId);
        if (!user) return res.status(401).json({ error: 'User not found' });
        res.json({ 
            user: { 
                id: user._id, 
                name: user.name, 
                email: user.email, 
                avatar: user.avatar, 
                bio: user.bio || '' 
            } 
        });
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

app.get('/api/users/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;
        const users = await User.find({ _id: { $ne: userId } }, { password: 0 });
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/user/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;
        const user = await User.findById(userId, { password: 0 });
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/user/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;
        const { bio } = req.body;
        const user = await User.findByIdAndUpdate(userId, { bio }, { new: true }).select('-password');
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/posts', async (req, res) => {
    try {
        const { userId, userName, userAvatar, content, image, video } = req.body;
        const post = new Post({ userId, userName, userAvatar, content, image, video });
        await post.save();
        res.json(post);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/posts', async (req, res) => {
    try {
        const posts = await Post.find().sort({ time: -1 });
        res.json(posts);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/posts/:postId/like', async (req, res) => {
    try {
        const post = await Post.findById(req.params.postId);
        if (!post) return res.status(404).json({ error: 'Post not found' });
        post.likes += 1;
        await post.save();
        res.json({ likes: post.likes });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/shop', async (req, res) => {
    try {
        const item = new ShopItem(req.body);
        await item.save();
        res.json(item);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/shop', async (req, res) => {
    try {
        const items = await ShopItem.find().sort({ createdAt: -1 });
        res.json(items);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/shop/:itemId/share', async (req, res) => {
    try {
        const item = await ShopItem.findById(req.params.itemId);
        if (!item) return res.status(404).json({ error: 'Item not found' });
        item.shares += 1;
        await item.save();
        res.json({ shares: item.shares });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/messages', async (req, res) => {
    try {
        const message = new Message(req.body);
        await message.save();
        res.json(message);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/messages/:userId/:otherId', async (req, res) => {
    try {
        const userId = req.params.userId;
        const otherId = req.params.otherId;
        const messages = await Message.find({
            $or: [
                { from: userId, to: otherId },
                { from: otherId, to: userId }
            ]
        }).sort({ time: 1 });
        res.json(messages);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/photos', async (req, res) => {
    try {
        const photo = new Photo(req.body);
        await photo.save();
        res.json(photo);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/photos', async (req, res) => {
    try {
        const photos = await Photo.find().sort({ time: -1 });
        res.json(photos);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/videos', async (req, res) => {
    try {
        const video = new Video(req.body);
        await video.save();
        res.json(video);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/videos', async (req, res) => {
    try {
        const videos = await Video.find().sort({ time: -1 });
        res.json(videos);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
