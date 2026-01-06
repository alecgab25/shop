// Store products in an array
let products = [];
let cart = [];
let currentDetailProductIndex = null;
let currentDetailImageIndex = 0;
let bankInfo = { account_name: '', account_number: '', instructions: '' };
let orders = [];
let productSearchQuery = '';
let backgrounds = {
    front_page: { color: '', image: '' },
    shop: { color: '', image: '' },
};
let currentUser = null; // { email }
const CLERK_PUBLISHABLE_KEY = 'pk_test_ZGl2ZXJzZS1pbnNlY3QtOTAuY2xlcmsuYWNjb3VudHMuZGV2JA';
let clerkReady = false;
let clerkLoader = null;

// --- ADMIN SYSTEM ---
let currentAdmin = null; // { email, is_owner }
let bootstrapNeeded = false;

async function apiFetch(path, options = {}) {
    const opts = { credentials: 'include', ...options };
    opts.headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
    const res = await fetch(path, opts);
    const contentType = res.headers.get('content-type') || '';
    const hasJson = contentType.includes('application/json');
    const data = hasJson ? await res.json().catch(() => null) : null;
    if (!res.ok) {
        const err = new Error((data && data.error) || 'Request failed');
        err.status = res.status;
        err.data = data;
        throw err;
    }
    return data;
}

// --- USER AUTH (Clerk) ---
function getClerkUserEmail(user) {
    if (!user) return '';
    if (user.primaryEmailAddress && user.primaryEmailAddress.emailAddress) {
        return user.primaryEmailAddress.emailAddress;
    }
    if (Array.isArray(user.emailAddresses) && user.emailAddresses.length > 0) {
        return user.emailAddresses[0].emailAddress || '';
    }
    return '';
}

function updateUserUI() {
    const signoutBtn = document.getElementById('front-signout-btn');
    if (signoutBtn) signoutBtn.style.display = currentUser ? 'inline-block' : 'none';
    const signinBtn = document.getElementById('front-signin-btn');
    if (signinBtn) signinBtn.style.display = currentUser ? 'none' : 'inline-block';
}

function syncClerkUser() {
    if (!window.Clerk) return;
    const user = window.Clerk.user || null;
    currentUser = user ? { email: getClerkUserEmail(user) || user.id } : null;
    if (!currentUser) currentAdmin = null;
    updateUserUI();
}

function loadClerkScript() {
    if (window.Clerk) return Promise.resolve();
    if (clerkLoader) return clerkLoader;
    clerkLoader = new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.async = true;
        script.crossOrigin = 'anonymous';
        script.src = 'https://js.clerk.dev/npm/clerk.browser.js';
        script.onload = () => resolve();
        script.onerror = () => reject(new Error('Clerk script failed to load.'));
        document.head.appendChild(script);
    });
    return clerkLoader;
}

async function initClerk() {
    if (clerkReady) return;
    await loadClerkScript();
    if (!window.Clerk) {
        console.error('Clerk script not loaded.');
        return;
    }
    await window.Clerk.load({ publishableKey: CLERK_PUBLISHABLE_KEY });
    syncClerkUser();
    if (typeof window.Clerk.addListener === 'function') {
        window.Clerk.addListener(syncClerkUser);
    }
    clerkReady = true;
}

async function showUserAuth(mode) {
    try {
        await initClerk();
    } catch (_err) {
        alert('Sign in is still loading. Please try again.');
        return;
    }
    if (!window.Clerk) {
        alert('Sign in is still loading. Please try again.');
        return;
    }
    if (mode === 'signin') {
        window.Clerk.openSignIn();
    } else {
        window.Clerk.openSignUp();
    }
}

async function userLogout() {
    if (window.Clerk) {
        await window.Clerk.signOut();
    }
    currentUser = null;
    currentAdmin = null;
    showAdminUI();
    updateUserUI();
}

async function hydrateUser() {
    syncClerkUser();
}

function showAdminUI() {
    const loggedIn = !!currentAdmin;
    const adminPanelBtn = document.getElementById('admin-panel-btn');
    if (adminPanelBtn) adminPanelBtn.style.display = loggedIn ? 'inline-block' : 'none';
    document.getElementById('add-product-section').style.display = loggedIn ? 'block' : 'none';
    const bgSection = document.getElementById('background-section');
    if (bgSection) bgSection.style.display = loggedIn ? 'block' : 'none';
    const frontBgBtn = document.getElementById('front-bg-btn');
    const shopBgBtn = document.getElementById('shop-bg-btn');
    if (frontBgBtn) frontBgBtn.style.display = loggedIn ? 'inline-block' : 'none';
    if (shopBgBtn) shopBgBtn.style.display = loggedIn ? 'inline-block' : 'none';
    const bankSection = document.getElementById('bank-info-section');
    if (bankSection) bankSection.style.display = isOwner() ? 'block' : 'none';
    const ordersSection = document.getElementById('orders-section');
    if (ordersSection) ordersSection.style.display = isOwner() ? 'block' : 'none';
    updateUserUI();
}

function isOwner() {
    return currentAdmin && currentAdmin.is_owner;
}

function canManageProducts() {
    return !!currentAdmin; // any logged-in admin (owner or not)
}

function showAdminLogin() {
    document.getElementById('admin-login-modal').style.display = 'flex';
    document.getElementById('admin-email-input').value = '';
    document.getElementById('admin-password-input').value = '';
    document.getElementById('admin-login-error').textContent = '';
    updateBootstrapUI();
}

function closeAdminLogin() {
    document.getElementById('admin-login-modal').style.display = 'none';
    document.getElementById('admin-password-input').value = '';
    document.getElementById('admin-email-input').value = '';
    document.getElementById('admin-login-error').textContent = '';
}

async function adminLogin() {
    const email = document.getElementById('admin-email-input').value.trim().toLowerCase();
    const password = document.getElementById('admin-password-input').value;
    const errorEl = document.getElementById('admin-login-error');
    errorEl.textContent = '';

    if (!email || !password) {
        errorEl.textContent = 'Email and password are required.';
        return;
    }

    try {
        const admin = await apiFetch('/api/sessions', {
            method: 'POST',
            body: JSON.stringify({ email, password })
        });
        currentAdmin = admin;
        await renderAdminList();
        showAdminUI();
        renderProducts(); // refresh product controls visibility
        populateBankForm();
        if (isOwner()) await loadOrders();
        closeAdminLogin();
    } catch (err) {
        errorEl.textContent = (err.data && err.data.error) || 'Login failed.';
    }
}

async function adminLogout() {
    try {
        await apiFetch('/api/sessions', { method: 'DELETE' });
    } catch (err) {
        // ignore logout errors
    }
    currentAdmin = null;
    showAdminUI();
    closeAdminPanel();
    renderProducts(); // hide product controls
    populateBankForm();
    orders = [];
    renderOrders();
}

async function bootstrapOwner() {
    const email = document.getElementById('bootstrap-email').value.trim().toLowerCase();
    const password = document.getElementById('bootstrap-password').value;
    const errorEl = document.getElementById('admin-login-error');
    errorEl.textContent = '';
    if (!email || !password) {
        errorEl.textContent = 'Owner email and password are required.';
        return;
    }
    try {
        await apiFetch('/api/admins/bootstrap', {
            method: 'POST',
            body: JSON.stringify({ email, password })
        });
        bootstrapNeeded = false;
        errorEl.textContent = 'Owner created. Please log in.';
        document.getElementById('bootstrap-email').value = '';
        document.getElementById('bootstrap-password').value = '';
        updateBootstrapUI();
    } catch (err) {
        errorEl.textContent = (err.data && err.data.error) || 'Could not create owner.';
    }
}

async function showAdminPanel() {
    if (!currentAdmin) {
        alert('You must be logged in as admin to access this panel.');
        return;
    }
    document.getElementById('current-admin-email').textContent = currentAdmin.email;
    await renderAdminList();
    const adminSection = document.querySelector('.admin-list-section');
    if (adminSection) adminSection.style.display = isOwner() ? 'block' : 'none';
    document.getElementById('admin-panel-modal').style.display = 'flex';
    document.getElementById('new-admin-email').value = '';
    document.getElementById('new-admin-password').value = '';
    populateBackgroundForm();
    if (isOwner()) await loadOrders();
}

function closeAdminPanel() {
    document.getElementById('admin-panel-modal').style.display = 'none';
}

async function addAdmin() {
    if (!isOwner()) {
        alert('Only the owner can add new admins.');
        return;
    }
    const newEmail = document.getElementById('new-admin-email').value.trim().toLowerCase();
    const newPassword = document.getElementById('new-admin-password').value;

    if (!newEmail || !newPassword) {
        alert('Please enter email and password.');
        return;
    }

    try {
        await apiFetch('/api/admins', {
            method: 'POST',
            body: JSON.stringify({ email: newEmail, password: newPassword })
        });
        document.getElementById('new-admin-email').value = '';
        document.getElementById('new-admin-password').value = '';
        await renderAdminList();
        alert('Admin added successfully!');
    } catch (err) {
        alert((err.data && err.data.error) || 'Could not add admin.');
    }
}

async function removeAdmin(id) {
    if (!isOwner()) {
        alert('Only the owner can remove admins.');
        return;
    }

    if (!confirm('Remove admin access?')) return;
    try {
        await apiFetch(`/api/admins/${id}`, { method: 'DELETE' });
        await renderAdminList();
    } catch (err) {
        alert((err.data && err.data.error) || 'Could not remove admin.');
    }
}

async function renderAdminList() {
    const list = document.getElementById('admin-list');
    list.innerHTML = '';
    if (!isOwner()) {
        list.innerHTML = '<li>Only the owner can manage admins.</li>';
        return;
    }
    try {
        const admins = await apiFetch('/api/admins');
        admins.forEach(admin => {
            const item = document.createElement('li');
            item.className = 'admin-list-item';
            item.innerHTML = `
                <span>${admin.email}</span>
                ${admin.is_owner ? '<span class="owner-badge">Owner</span>' : ''}
                ${admin.is_owner ? '' : `<button onclick="removeAdmin(${admin.id})" class="remove-admin-btn">Remove</button>`}
            `;
            list.appendChild(item);
        });
    } catch (err) {
        list.innerHTML = '<li>Could not load admins.</li>';
    }
}

async function checkBootstrapStatus() {
    try {
        const data = await apiFetch('/api/admins/has-admin');
        bootstrapNeeded = !data.hasAdmin;
    } catch (err) {
        bootstrapNeeded = false;
    }
    updateBootstrapUI();
}

function updateBootstrapUI() {
    const section = document.getElementById('bootstrap-section');
    if (!section) return;
    section.style.display = bootstrapNeeded ? 'block' : 'none';
}

async function hydrateSession() {
    await checkBootstrapStatus();
    try {
        const session = await apiFetch('/api/session');
        currentAdmin = session;
    } catch (err) {
        currentAdmin = null;
    }
    showAdminUI();
    // Ensure product controls (delete/add images) reflect restored admin session after reload
    renderProducts();
    populateBankForm();
    if (isOwner()) await loadOrders();
}
// --- END ADMIN SYSTEM ---

// Load products from localStorage if available
function loadProducts() {
    const saved = localStorage.getItem('products');
    if (saved) {
        products = JSON.parse(saved);
    } else {
        products = [];
    }
}
function saveProducts() {
    localStorage.setItem('products', JSON.stringify(products));
}
// --- CART ---
function loadCart() {
    const saved = localStorage.getItem('cart');
    if (saved) {
        cart = JSON.parse(saved);
    } else {
        cart = [];
    }
}
function saveCart() {
    localStorage.setItem('cart', JSON.stringify(cart));
}
function addToCart(productIdx) {
    cart.push(products[productIdx]);
    saveCart();
    renderCart();
}
function removeFromCart(cartIdx) {
    cart.splice(cartIdx, 1);
    saveCart();
    renderCart();
}
function renderCart() {
    // Cart badge
    const cartCountEl = document.getElementById('cart-count');
    if (cart.length > 0) {
        cartCountEl.textContent = cart.length;
        cartCountEl.style.display = 'inline-block';
    } else {
        cartCountEl.textContent = '';
        cartCountEl.style.display = 'none';
    }
    // Dropdown content
    const list = document.getElementById('cart-list');
    if (!list) return; // on front page
    list.innerHTML = '';
    if (cart.length === 0) {
        list.innerHTML = '<li>Cart is empty!</li>';
    } else {
        cart.forEach((product, idx) => {
            const item = document.createElement('li');
            if (product.images && product.images[0]) {
                const img = document.createElement('img');
                img.src = product.images[0];
                img.alt = product.name;
                img.style.width = '36px';
                img.style.height = '36px';
                img.style.objectFit = 'cover';
                img.style.borderRadius = '4px';
                item.appendChild(img);
            }
            const info = document.createElement('span');
            info.textContent = `${product.name} - CA$${product.price.toFixed(2)}`;
            item.appendChild(info);
            const delBtn = document.createElement('button');
            delBtn.textContent = 'Remove';
            delBtn.className = 'cart-remove-btn';
            delBtn.onclick = () => { removeFromCart(idx); closeCartDropdown(); toggleCartDropdown(true); };
            item.appendChild(delBtn);
            list.appendChild(item);
        });
    }
    let total = cart.reduce((sum, p) => sum + (p.price||0), 0);
    document.getElementById('cart-total').textContent = total > 0 ? `Total: CA$${total.toFixed(2)}` : '';
    const checkoutBtn = document.getElementById('checkout-btn');
    if (checkoutBtn) {
        checkoutBtn.disabled = cart.length === 0;
        checkoutBtn.style.opacity = cart.length === 0 ? '0.5' : '1';
        checkoutBtn.style.cursor = cart.length === 0 ? 'not-allowed' : 'pointer';
    }
}
function toggleCartDropdown(forceOpen) {
    const dropdown = document.getElementById('cart-dropdown');
    if (!dropdown) return;
    // Optional: only one open, e.g. on mobile, can extend
    if (forceOpen) {
        dropdown.style.display = 'block';
        document.addEventListener('mousedown', handleCartOutsideClick);
        return;
    }
    if (dropdown.style.display === 'block') {
        dropdown.style.display = 'none';
        document.removeEventListener('mousedown', handleCartOutsideClick);
    } else {
        dropdown.style.display = 'block';
        document.addEventListener('mousedown', handleCartOutsideClick);
    }
}
function closeCartDropdown() {
    const dropdown = document.getElementById('cart-dropdown');
    if (!dropdown) return;
    dropdown.style.display = 'none';
    document.removeEventListener('mousedown', handleCartOutsideClick);
}
function handleCartOutsideClick(e) {
    const dropdown = document.getElementById('cart-dropdown');
    const btn = document.getElementById('cart-icon-btn');
    if (dropdown && !dropdown.contains(e.target) && btn && !btn.contains(e.target)) {
        closeCartDropdown();
    }
}
// -------

// --- Backgrounds ---
function applyBackgrounds() {
    const front = backgrounds.front_page || {};
    const shop = backgrounds.shop || {};
    const frontEl = document.querySelector('.front-page');
    if (frontEl) {
        frontEl.style.backgroundColor = front.color || '';
        if (front.image) {
            frontEl.style.backgroundImage = `url('${front.image}')`;
            frontEl.style.backgroundSize = 'cover';
            frontEl.style.backgroundPosition = 'center';
        } else {
            frontEl.style.backgroundImage = '';
            frontEl.style.backgroundSize = '';
            frontEl.style.backgroundPosition = '';
        }
    }
    const shopEl = document.getElementById('shop-section');
    if (shopEl) {
        shopEl.style.backgroundColor = shop.color || '';
        if (shop.image) {
            shopEl.style.backgroundImage = `url('${shop.image}')`;
            shopEl.style.backgroundSize = 'cover';
            shopEl.style.backgroundPosition = 'center';
        } else {
            shopEl.style.backgroundImage = '';
            shopEl.style.backgroundSize = '';
            shopEl.style.backgroundPosition = '';
        }
    }
}

function populateBackgroundForm() {
    const frontColor = document.getElementById('bg-front-color');
    const frontImage = document.getElementById('bg-front-image');
    const shopColor = document.getElementById('bg-shop-color');
    const shopImage = document.getElementById('bg-shop-image');
    if (!frontColor || !frontImage || !shopColor || !shopImage) return;
    frontColor.value = backgrounds.front_page?.color || '';
    frontImage.value = backgrounds.front_page?.image || '';
    shopColor.value = backgrounds.shop?.color || '';
    shopImage.value = backgrounds.shop?.image || '';
    const statusEl = document.getElementById('background-save-status');
    if (statusEl) statusEl.textContent = '';
}

async function fetchBackgrounds() {
    try {
        const data = await apiFetch('/api/backgrounds');
        backgrounds = data || backgrounds;
    } catch (_err) {
        backgrounds = backgrounds || {
            front_page: { color: '', image: '' },
            shop: { color: '', image: '' },
        };
    }
    applyBackgrounds();
    populateBackgroundForm();
}

async function saveBackgrounds() {
    if (!canManageProducts()) {
        alert('Only admins can change backgrounds.');
        return;
    }
    const statusEl = document.getElementById('background-save-status');
    if (statusEl) statusEl.textContent = 'Saving...';
    const payload = {
        front_page: {
            color: (document.getElementById('bg-front-color')?.value || '').trim(),
            image: (document.getElementById('bg-front-image')?.value || '').trim(),
        },
        shop: {
            color: (document.getElementById('bg-shop-color')?.value || '').trim(),
            image: (document.getElementById('bg-shop-image')?.value || '').trim(),
        },
    };
    try {
        await apiFetch('/api/backgrounds', { method: 'PUT', body: JSON.stringify(payload) });
        backgrounds = payload;
        applyBackgrounds();
        if (statusEl) statusEl.textContent = 'Saved';
    } catch (_err) {
        if (statusEl) statusEl.textContent = 'Could not save';
    }
}

function openBackgroundPicker(targetKey) {
    if (!canManageProducts()) {
        alert('Only admins can change backgrounds.');
        return;
    }
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = 'image/*';
    input.style.display = 'none';
    input.onchange = function() {
        if (!input.files || !input.files[0]) return;
        const reader = new FileReader();
        reader.onload = async function(e) {
            const dataUrl = e.target.result || '';
            const payload = {
                front_page: { ...backgrounds.front_page },
                shop: { ...backgrounds.shop },
            };
            payload[targetKey] = payload[targetKey] || { color: '', image: '' };
            payload[targetKey].image = dataUrl;
            try {
                await apiFetch('/api/backgrounds', { method: 'PUT', body: JSON.stringify(payload) });
                backgrounds = payload;
                applyBackgrounds();
                populateBackgroundForm();
                const statusEl = document.getElementById('background-save-status');
                if (statusEl) statusEl.textContent = 'Saved';
            } catch (_err) {
                alert('Could not save background.');
            }
        };
        reader.readAsDataURL(input.files[0]);
    };
    document.body.appendChild(input);
    input.click();
    document.body.removeChild(input);
}

// --- Bank info (owner managed) ---
async function fetchBankInfo() {
    try {
        const info = await apiFetch('/api/bank-info');
        bankInfo = info || { account_name: '', account_number: '', instructions: '' };
        renderBankInfoDisplay();
        populateBankForm();
    } catch (_err) {
        bankInfo = { account_name: '', account_number: '', instructions: '' };
        renderBankInfoDisplay();
    }
}

function renderBankInfoDisplay() {
    const inline = document.getElementById('bank-info-inline');
    if (inline) {
        if (bankInfo.account_number || bankInfo.instructions) {
            inline.textContent = `Pay to: ${bankInfo.account_name || ''} ${bankInfo.account_number || ''}`.trim();
        } else {
            inline.textContent = 'Owner has not set bank details yet.';
        }
    }
    const checkoutInfo = document.getElementById('checkout-bank-info');
    if (checkoutInfo) {
        if (bankInfo.account_number || bankInfo.instructions) {
            checkoutInfo.textContent = `${bankInfo.account_name || ''} ${bankInfo.account_number || ''} ${bankInfo.instructions || ''}`.trim();
        } else {
            checkoutInfo.textContent = 'Owner has not set bank details yet.';
        }
    }
}

function populateBankForm() {
    const nameInput = document.getElementById('bank-account-name');
    const numInput = document.getElementById('bank-account-number');
    const instrInput = document.getElementById('bank-instructions');
    const statusEl = document.getElementById('bank-info-save-status');
    if (!nameInput || !numInput || !instrInput) return;
    if (isOwner()) {
        nameInput.value = bankInfo.account_name || '';
        numInput.value = bankInfo.account_number || '';
        instrInput.value = bankInfo.instructions || '';
    } else {
        nameInput.value = '';
        numInput.value = '';
        instrInput.value = '';
    }
    if (statusEl) statusEl.textContent = '';
}

async function saveBankInfo() {
    if (!isOwner()) return;
    const statusEl = document.getElementById('bank-info-save-status');
    try {
        const payload = {
            account_name: document.getElementById('bank-account-name').value.trim(),
            account_number: document.getElementById('bank-account-number').value.trim(),
            instructions: document.getElementById('bank-instructions').value.trim(),
        };
        await apiFetch('/api/bank-info', { method: 'PUT', body: JSON.stringify(payload) });
        if (statusEl) statusEl.textContent = 'Saved';
        await fetchBankInfo();
    } catch (_err) {
        if (statusEl) statusEl.textContent = 'Could not save';
    }
}

// --- Orders (owner view) ---
async function loadOrders() {
    if (!isOwner()) return;
    try {
        const data = await apiFetch('/api/orders');
        orders = data || [];
        renderOrders();
    } catch (_err) {
        orders = [];
        renderOrders(true);
    }
}

function renderOrders(failed = false) {
    const container = document.getElementById('orders-list');
    if (!container) return;
    if (failed) {
        container.innerHTML = '<div class="order-card">Could not load orders.</div>';
        return;
    }
    if (!orders.length) {
        container.innerHTML = '<div class="order-card">No orders yet.</div>';
        return;
    }
    container.innerHTML = '';
    orders.forEach((order) => {
        const div = document.createElement('div');
        div.className = 'order-card';
        const addr = [order.address_line, order.city, order.region, order.postal_code]
            .filter(Boolean)
            .join(', ');
        const itemsText = formatOrderItems(order.items);
        div.innerHTML = `
            <div><strong>${order.customer_name || 'Customer'}</strong> ${order.email ? '(' + order.email + ')' : ''}</div>
            <div class="order-address">${addr}</div>
            <div class="order-total">Total: CA$${(Number(order.total_cents || 0) / 100).toFixed(2)}</div>
            <div class="order-items">Items: ${itemsText}</div>
            <div class="order-date">${order.created_at || ''}</div>
        `;
        container.appendChild(div);
    });
}

function formatOrderItems(items) {
    if (!items || !items.length) return 'None';
    return items
        .map((it) => `${it.name || 'Item'}${typeof it.price === 'number' ? ' (CA$' + it.price.toFixed(2) + ')' : ''}`)
        .join(', ');
}

// --- Checkout / orders ---
function startCheckout() {
    if (cart.length === 0) {
        alert('Your cart is empty.');
        return;
    }
    renderBankInfoDisplay();
    document.getElementById('checkout-error').textContent = '';
    document.getElementById('checkout-name').value = '';
    document.getElementById('checkout-email').value = '';
    document.getElementById('checkout-address').value = '';
    document.getElementById('checkout-city').value = '';
    document.getElementById('checkout-region').value = '';
    document.getElementById('checkout-postal').value = '';
    const modal = document.getElementById('checkout-modal');
    if (modal) modal.style.display = 'flex';
}

function closeCheckout() {
    const modal = document.getElementById('checkout-modal');
    if (modal) modal.style.display = 'none';
}

async function submitOrder() {
    const errorEl = document.getElementById('checkout-error');
    const name = document.getElementById('checkout-name').value.trim();
    const email = document.getElementById('checkout-email').value.trim();
    const address = document.getElementById('checkout-address').value.trim();
    const city = document.getElementById('checkout-city').value.trim();
    const region = document.getElementById('checkout-region').value.trim();
    const postal = document.getElementById('checkout-postal').value.trim();
    if (!name || !address || !city || !postal) {
        if (errorEl) errorEl.textContent = 'Name, address, city, and postal code are required.';
        return;
    }
    const total = cart.reduce((sum, p) => sum + (p.price || 0), 0);
    try {
        await apiFetch('/api/orders', {
            method: 'POST',
            body: JSON.stringify({
                customer_name: name,
                email,
                address_line: address,
                city,
                region,
                postal_code: postal,
                items: cart,
                total,
            }),
        });
        cart = [];
        saveCart();
        renderCart();
        closeCheckout();
        alert('Order placed! Follow the payment instructions to complete your purchase.');
        if (isOwner()) await loadOrders();
    } catch (err) {
        if (errorEl) errorEl.textContent = (err.data && err.data.error) || 'Could not place order.';
    }
}

function enterShop() {
    document.getElementById('front-page').style.display = 'none';
    document.getElementById('shop-section').style.display = '';
    // set message in shop page (remains for compatibility if message still in localStorage)
    const savedMsg = localStorage.getItem('shopMessage') || '';
    const savedMsgEl = document.getElementById('saved-shop-message');
    if (savedMsgEl) savedMsgEl.textContent = savedMsg;
    // Check admin status when entering shop
    hydrateSession();
}

function returnToFront() {
    document.getElementById('front-page').style.display = '';
    document.getElementById('shop-section').style.display = 'none';
    closeCartDropdown();
}

function addProduct() {
    if (!canManageProducts()) {
        alert('Only admins can add products. Please log in as admin.');
        return;
    }
    const nameInput = document.getElementById('product-name');
    const priceInput = document.getElementById('product-price');
    const fileInput = document.getElementById('product-image-file');
    const name = nameInput.value.trim();
    const price = parseFloat(priceInput.value);
    const files = fileInput.files;
    if (!name || isNaN(price) || price <= 0) {
        alert('Please enter a valid product name and price.');
        return;
    }
    if (files && files.length > 0) {
        const readers = [];
        const images = [];
        let loadedCount = 0;
        for (let i = 0; i < files.length; i++) {
            readers[i] = new FileReader();
            readers[i].onload = function(e) {
                images[i] = e.target.result;
                loadedCount++;
                if (loadedCount === files.length) {
                    products.push({ name, price, images });
                    saveProducts();
                    nameInput.value = '';
                    priceInput.value = '';
                    fileInput.value = '';
                    document.getElementById('image-preview-container').innerHTML = '';
                    renderProducts();
                }
            };
            readers[i].readAsDataURL(files[i]);
        }
    } else {
        products.push({ name, price, images: [] });
        saveProducts();
        nameInput.value = '';
        priceInput.value = '';
        fileInput.value = '';
        document.getElementById('image-preview-container').innerHTML = '';
        renderProducts();
    }
}

function addImagesToProduct(index, files) {
    if (!canManageProducts()) {
        alert('Only admins can add images to products.');
        return;
    }
    if (!files || files.length === 0) return;
    const readers = [];
    let loadedCount = 0;
    const imagesToAdd = [];
    for (let i = 0; i < files.length; i++) {
        readers[i] = new FileReader();
        readers[i].onload = function(e) {
            imagesToAdd[i] = e.target.result;
            loadedCount++;
            if (loadedCount === files.length) {
                if (!products[index].images) products[index].images = [];
                products[index].images = products[index].images.concat(imagesToAdd);
                saveProducts();
                renderProducts();
            }
        };
        readers[i].readAsDataURL(files[i]);
    }
}

function deleteProduct(index) {
    if (!canManageProducts()) {
        alert('Only admins can delete products.');
        return;
    }
    if (confirm('Delete this product?')) {
        products.splice(index, 1);
        saveProducts();
        renderProducts();
    }
}

function renderProducts() {
    const list = document.getElementById('product-list');
    list.innerHTML = '';
    const filtered = getFilteredProducts();
    if (products.length === 0) {
        list.innerHTML = '<li>No products yet!</li>';
    } else if (filtered.length === 0) {
        list.innerHTML = '<li>No products match your search.</li>';
    } else {
        let firstItem = null;
        filtered.forEach(({ product, idx }) => {
            const item = document.createElement('li');
            item.className = 'product-item';
            item.onclick = () => openProductDetail(idx);
            if (product.images && product.images.length > 0) {
                const imagesDiv = document.createElement('div');
                imagesDiv.className = 'multi-product-images';
                product.images.forEach(imgData => {
                    const img = document.createElement('img');
                    img.src = imgData;
                    img.alt = product.name;
                    img.className = 'product-img';
                    imagesDiv.appendChild(img);
                });
                item.appendChild(imagesDiv);
            }
            const info = document.createElement('span');
            info.textContent = `${product.name} - CA$${product.price.toFixed(2)}`;
            item.appendChild(info);
            // Add to cart button (always visible)
            const addCartBtn = document.createElement('button');
            addCartBtn.textContent = 'Add to Cart';
            addCartBtn.className = 'add-img-btn';
            addCartBtn.onclick = (e) => { e.stopPropagation(); addToCart(idx); };
            item.appendChild(addCartBtn);
            
            // Admin-only buttons
            if (canManageProducts()) {
                // Add Image
                const imgForm = document.createElement('form');
                imgForm.style.display = 'inline';
                imgForm.onsubmit = e => e.preventDefault();
                const addImgBtn = document.createElement('button');
                addImgBtn.textContent = 'Add Image';
                addImgBtn.type = 'button';
                addImgBtn.className = 'add-img-btn';
                const imgInput = document.createElement('input');
                imgInput.type = 'file';
                imgInput.style.display = 'none';
                imgInput.accept = 'image/*';
                imgInput.multiple = true;
                addImgBtn.onclick = (e) => { e.stopPropagation(); imgInput.click(); };
                imgInput.onchange = function() {
                    addImagesToProduct(idx, imgInput.files);
                    imgInput.value = '';
                };
                imgForm.appendChild(addImgBtn);
                imgForm.appendChild(imgInput);
                item.appendChild(imgForm);
                
                // Delete button
                const delBtn = document.createElement('button');
                delBtn.textContent = 'Delete';
                delBtn.className = 'delete-btn';
                delBtn.onclick = (e) => { e.stopPropagation(); deleteProduct(idx); };
                item.appendChild(delBtn);
            }
            list.appendChild(item);
            if (!firstItem) firstItem = item;
        });
        if (productSearchQuery && firstItem) {
            firstItem.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
    }
}

// --- Product detail modal ---
function openProductDetail(idx) {
    currentDetailProductIndex = idx;
    currentDetailImageIndex = 0;
    updateProductModal();
    const modal = document.getElementById('product-modal');
    if (modal) modal.style.display = 'flex';
}

function closeProductDetail() {
    const modal = document.getElementById('product-modal');
    if (modal) modal.style.display = 'none';
    currentDetailProductIndex = null;
    currentDetailImageIndex = 0;
}

function updateProductModal() {
    if (currentDetailProductIndex === null) return;
    const product = products[currentDetailProductIndex];
    if (!product) return;
    const nameEl = document.getElementById('product-modal-name');
    const priceEl = document.getElementById('product-modal-price');
    const imgEl = document.getElementById('product-modal-image');
    const indicatorEl = document.getElementById('product-modal-indicator');
    if (nameEl) nameEl.textContent = product.name;
    if (priceEl) priceEl.textContent = `CA$${Number(product.price || 0).toFixed(2)}`;
    const imgs = product.images && product.images.length > 0 ? product.images : [];
    const imgSrc = imgs[currentDetailImageIndex] || imgs[0] || '';
    if (imgEl) {
        imgEl.src = imgSrc || '';
        imgEl.alt = product.name || 'Product image';
    }
    if (indicatorEl) {
        if (imgs.length <= 1) {
            indicatorEl.textContent = '';
        } else {
            indicatorEl.textContent = `${currentDetailImageIndex + 1} / ${imgs.length}`;
        }
    }
}

function nextProductImage() {
    if (currentDetailProductIndex === null) return;
    const product = products[currentDetailProductIndex];
    const imgs = product.images && product.images.length > 0 ? product.images : [];
    if (imgs.length <= 1) return;
    currentDetailImageIndex = (currentDetailImageIndex + 1) % imgs.length;
    updateProductModal();
}

function prevProductImage() {
    if (currentDetailProductIndex === null) return;
    const product = products[currentDetailProductIndex];
    const imgs = product.images && product.images.length > 0 ? product.images : [];
    if (imgs.length <= 1) return;
    currentDetailImageIndex = (currentDetailImageIndex - 1 + imgs.length) % imgs.length;
    updateProductModal();
}

// --- Search ---
function handleProductSearch(query) {
    productSearchQuery = (query || '').toLowerCase();
    renderProducts();
}

function getFilteredProducts() {
    if (!productSearchQuery) {
        return products.map((p, idx) => ({ product: p, idx }));
    }
    return products
        .map((p, idx) => ({ product: p, idx }))
        .filter(({ product }) => (product.name || '').toLowerCase().includes(productSearchQuery));
}

// Image preview for add form
const imageInputEl = document.getElementById('product-image-file');
if (imageInputEl) {
    imageInputEl.addEventListener('change', function() {
        const preview = document.getElementById('image-preview-container');
        preview.innerHTML = '';
        for (let i = 0; i < this.files.length; i++) {
            const reader = new FileReader();
            reader.onload = function(e) {
                const img = document.createElement('img');
                img.src = e.target.result;
                img.className = 'product-img';
                preview.appendChild(img);
            };
            reader.readAsDataURL(this.files[i]);
        }
    });
}

function saveAndScrollToShop() {
    const msg = document.getElementById('shop-message').value.trim();
    localStorage.setItem('shopMessage', msg);
    document.getElementById('saved-shop-message').textContent = msg;
    // scroll smoothly to the shop-section
    document.getElementById('shop-section').scrollIntoView({ behavior: 'smooth' });
}

function saveShopMessage() {
    const msg = document.getElementById('shop-message').value.trim();
    localStorage.setItem('shopMessage', msg);
    document.getElementById('saved-shop-message').textContent = msg;
}
function scrollToShop() {
    saveShopMessage();
    document.getElementById('shop-section').scrollIntoView({ behavior: 'smooth' });
}

document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('front-page').style.display = '';
    document.getElementById('shop-section').style.display = 'none';
    // set shop message in shop-section if any (compatibility)
    const savedMsg = localStorage.getItem('shopMessage') || '';
    const savedMsgEl = document.getElementById('saved-shop-message');
    if (savedMsgEl) savedMsgEl.textContent = savedMsg;
    
    // Initialize admin system
    hydrateSession();
    initClerk();
    hydrateUser();
    fetchBackgrounds();
    updateUserUI();
    
    loadProducts();
    loadCart();
    renderProducts();
    renderCart();
    fetchBankInfo();
    loadOrders();
    const newImageInputEl = document.getElementById('product-image-file');
    if (newImageInputEl) {
        newImageInputEl.addEventListener('change', function() {
            const preview = document.getElementById('image-preview-container');
            preview.innerHTML = '';
            for (let i = 0; i < this.files.length; i++) {
                const reader = new FileReader();
                reader.onload = function(e) {
                    const img = document.createElement('img');
                    img.src = e.target.result;
                    img.className = 'product-img';
                    preview.appendChild(img);
                };
                reader.readAsDataURL(this.files[i]);
            }
        });
    }
    
    // Close modals when clicking outside
    window.onclick = function(event) {
        const loginModal = document.getElementById('admin-login-modal');
        const panelModal = document.getElementById('admin-panel-modal');
        const productModal = document.getElementById('product-modal');
        const checkoutModal = document.getElementById('checkout-modal');
        if (event.target === loginModal) {
            closeAdminLogin();
        }
        if (event.target === panelModal) {
            closeAdminPanel();
        }
        if (event.target === productModal) {
            closeProductDetail();
        }
        if (event.target === checkoutModal) {
            closeCheckout();
        }
    }
});

// Expose handlers to window for inline HTML onclick bindings
window.showAdminLogin = showAdminLogin;
window.closeAdminLogin = closeAdminLogin;
window.adminLogin = adminLogin;
window.bootstrapOwner = bootstrapOwner;
window.showAdminPanel = showAdminPanel;
window.closeAdminPanel = closeAdminPanel;
window.addAdmin = addAdmin;
window.removeAdmin = removeAdmin;
window.adminLogout = adminLogout;
window.saveBankInfo = saveBankInfo;
window.loadOrders = loadOrders;
window.startCheckout = startCheckout;
window.closeCheckout = closeCheckout;
window.submitOrder = submitOrder;
window.enterShop = enterShop;
window.returnToFront = returnToFront;
window.addProduct = addProduct;
window.addImagesToProduct = addImagesToProduct;
window.deleteProduct = deleteProduct;
window.handleProductSearch = handleProductSearch;
window.openProductDetail = openProductDetail;
window.closeProductDetail = closeProductDetail;
window.nextProductImage = nextProductImage;
window.prevProductImage = prevProductImage;
window.openBackgroundPicker = openBackgroundPicker;
window.saveBackgrounds = saveBackgrounds;
window.showUserAuth = showUserAuth;
window.userLogout = userLogout;
