PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS USERS (
  userID TEXT PRIMARY KEY,
  firstName TEXT NOT NULL,
  lastName TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  passwordHash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','teacher','student','parent')),
  classID TEXT,
  gradeLevel TEXT,
  walletID TEXT,
  xp INTEGER NOT NULL DEFAULT 0,
  level INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected','suspended')),
  profileFileID TEXT,
  createdAt TEXT NOT NULL,
  lastLoginAt TEXT,
  failedLoginAttempts INTEGER NOT NULL DEFAULT 0,
  lockedUntil TEXT
);
CREATE INDEX IF NOT EXISTS idx_users_role_status ON USERS(role,status);
CREATE INDEX IF NOT EXISTS idx_users_class ON USERS(classID);

CREATE TABLE IF NOT EXISTS SESSIONS (
  sessionID TEXT PRIMARY KEY,
  sessionTokenHash TEXT NOT NULL UNIQUE,
  userID TEXT NOT NULL REFERENCES USERS(userID) ON DELETE CASCADE,
  createdAt TEXT NOT NULL,
  expiresAt TEXT NOT NULL,
  lastActivityAt TEXT NOT NULL,
  ipHash TEXT,
  userAgent TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked','expired'))
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON SESSIONS(userID,status);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON SESSIONS(expiresAt);

CREATE TABLE IF NOT EXISTS FILES (
  fileID TEXT PRIMARY KEY,
  ownerID TEXT NOT NULL REFERENCES USERS(userID) ON DELETE CASCADE,
  r2Key TEXT NOT NULL UNIQUE,
  originalName TEXT NOT NULL,
  mimeType TEXT NOT NULL,
  fileSize INTEGER NOT NULL DEFAULT 0,
  category TEXT NOT NULL DEFAULT 'attachment',
  visibility TEXT NOT NULL DEFAULT 'private' CHECK (visibility IN ('private','public')),
  createdAt TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','ready','failed','deleted'))
);
CREATE INDEX IF NOT EXISTS idx_files_owner ON FILES(ownerID,status);

CREATE TABLE IF NOT EXISTS POSTS (
  postID TEXT PRIMARY KEY,
  userID TEXT NOT NULL REFERENCES USERS(userID) ON DELETE CASCADE,
  postType TEXT NOT NULL CHECK (postType IN ('text','image','youtube','file')),
  content TEXT,
  targetType TEXT NOT NULL CHECK (targetType IN ('school','class','subject')),
  targetID TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected','deleted')),
  rejectionReason TEXT,
  createdAt TEXT NOT NULL,
  updatedAt TEXT NOT NULL,
  pinned INTEGER NOT NULL DEFAULT 0,
  reportCount INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_posts_feed ON POSTS(status,pinned,createdAt DESC);
CREATE INDEX IF NOT EXISTS idx_posts_target ON POSTS(targetType,targetID,createdAt DESC);

CREATE TABLE IF NOT EXISTS POST_FILES (
  postFileID TEXT PRIMARY KEY,
  postID TEXT NOT NULL REFERENCES POSTS(postID) ON DELETE CASCADE,
  fileID TEXT NOT NULL REFERENCES FILES(fileID) ON DELETE RESTRICT,
  sortOrder INTEGER NOT NULL DEFAULT 0,
  UNIQUE(postID,fileID)
);

CREATE TABLE IF NOT EXISTS REACTIONS (
  reactionID TEXT PRIMARY KEY,
  postID TEXT NOT NULL REFERENCES POSTS(postID) ON DELETE CASCADE,
  userID TEXT NOT NULL REFERENCES USERS(userID) ON DELETE CASCADE,
  reactionType TEXT NOT NULL CHECK (reactionType IN ('like','clap','agree')),
  createdAt TEXT NOT NULL,
  UNIQUE(postID,userID)
);

CREATE TABLE IF NOT EXISTS COMMENTS (
  commentID TEXT PRIMARY KEY,
  postID TEXT NOT NULL REFERENCES POSTS(postID) ON DELETE CASCADE,
  userID TEXT NOT NULL REFERENCES USERS(userID) ON DELETE CASCADE,
  content TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'approved' CHECK (status IN ('pending','approved','rejected','deleted')),
  createdAt TEXT NOT NULL,
  updatedAt TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_comments_post ON COMMENTS(postID,createdAt);

CREATE TABLE IF NOT EXISTS POST_REPORTS (
  reportID TEXT PRIMARY KEY,
  postID TEXT NOT NULL REFERENCES POSTS(postID) ON DELETE CASCADE,
  userID TEXT NOT NULL REFERENCES USERS(userID) ON DELETE CASCADE,
  reason TEXT NOT NULL,
  createdAt TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','reviewed','dismissed')),
  UNIQUE(postID,userID)
);

CREATE TABLE IF NOT EXISTS CLASSES (
  classID TEXT PRIMARY KEY,
  className TEXT NOT NULL,
  subjectName TEXT NOT NULL,
  teacherID TEXT NOT NULL REFERENCES USERS(userID) ON DELETE RESTRICT,
  gradeLevel TEXT,
  room TEXT,
  academicYear TEXT NOT NULL,
  semester TEXT NOT NULL,
  joinCode TEXT UNIQUE,
  coverFileID TEXT REFERENCES FILES(fileID) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed','archived')),
  createdAt TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_classes_teacher ON CLASSES(teacherID,status);

CREATE TABLE IF NOT EXISTS CLASS_MEMBERS (
  memberID TEXT PRIMARY KEY,
  classID TEXT NOT NULL REFERENCES CLASSES(classID) ON DELETE CASCADE,
  userID TEXT NOT NULL REFERENCES USERS(userID) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'student' CHECK (role IN ('teacher','student')),
  joinedAt TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  UNIQUE(classID,userID)
);
CREATE INDEX IF NOT EXISTS idx_class_members_user ON CLASS_MEMBERS(userID,status);

CREATE TABLE IF NOT EXISTS LESSONS (
  lessonID TEXT PRIMARY KEY,
  classID TEXT NOT NULL REFERENCES CLASSES(classID) ON DELETE CASCADE,
  orderIndex INTEGER NOT NULL,
  title TEXT NOT NULL,
  content TEXT,
  youtubeVideoID TEXT,
  publishedAt TEXT,
  unlockType TEXT NOT NULL DEFAULT 'none' CHECK (unlockType IN ('none','previous_complete','specific')),
  unlockLessonID TEXT REFERENCES LESSONS(lessonID) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','published','archived')),
  createdAt TEXT NOT NULL,
  updatedAt TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lessons_class_order ON LESSONS(classID,orderIndex);

CREATE TABLE IF NOT EXISTS LESSON_FILES (
  lessonFileID TEXT PRIMARY KEY,
  lessonID TEXT NOT NULL REFERENCES LESSONS(lessonID) ON DELETE CASCADE,
  fileID TEXT NOT NULL REFERENCES FILES(fileID) ON DELETE RESTRICT,
  sortOrder INTEGER NOT NULL DEFAULT 0,
  UNIQUE(lessonID,fileID)
);

CREATE TABLE IF NOT EXISTS LESSON_PROGRESS (
  progressID TEXT PRIMARY KEY,
  lessonID TEXT NOT NULL REFERENCES LESSONS(lessonID) ON DELETE CASCADE,
  userID TEXT NOT NULL REFERENCES USERS(userID) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'started' CHECK (status IN ('started','completed')),
  percentage REAL NOT NULL DEFAULT 0,
  startedAt TEXT NOT NULL,
  completedAt TEXT,
  updatedAt TEXT NOT NULL,
  UNIQUE(lessonID,userID)
);

CREATE TABLE IF NOT EXISTS ASSIGNMENTS (
  assignID TEXT PRIMARY KEY,
  classID TEXT NOT NULL REFERENCES CLASSES(classID) ON DELETE CASCADE,
  teacherID TEXT NOT NULL REFERENCES USERS(userID) ON DELETE RESTRICT,
  title TEXT NOT NULL,
  description TEXT,
  maxScore REAL NOT NULL,
  assignedAt TEXT NOT NULL,
  dueAt TEXT NOT NULL,
  acceptedFileTypes TEXT,
  allowLate INTEGER NOT NULL DEFAULT 0,
  latePenaltyPercent REAL NOT NULL DEFAULT 0,
  exampleFileID TEXT REFERENCES FILES(fileID) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('draft','open','locked','archived')),
  createdAt TEXT NOT NULL,
  updatedAt TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_assignments_class_due ON ASSIGNMENTS(classID,dueAt,status);

CREATE TABLE IF NOT EXISTS SUBMISSIONS (
  submitID TEXT PRIMARY KEY,
  assignID TEXT NOT NULL REFERENCES ASSIGNMENTS(assignID) ON DELETE CASCADE,
  userID TEXT NOT NULL REFERENCES USERS(userID) ON DELETE CASCADE,
  content TEXT,
  submittedAt TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'submitted' CHECK (status IN ('draft','submitted','graded','returned')),
  isLate INTEGER NOT NULL DEFAULT 0,
  score REAL,
  feedback TEXT,
  gradedAt TEXT,
  gradedBy TEXT REFERENCES USERS(userID) ON DELETE SET NULL,
  updatedAt TEXT NOT NULL,
  UNIQUE(assignID,userID)
);
CREATE INDEX IF NOT EXISTS idx_submissions_assignment ON SUBMISSIONS(assignID,status);

CREATE TABLE IF NOT EXISTS SUBMISSION_FILES (
  submissionFileID TEXT PRIMARY KEY,
  submitID TEXT NOT NULL REFERENCES SUBMISSIONS(submitID) ON DELETE CASCADE,
  fileID TEXT NOT NULL REFERENCES FILES(fileID) ON DELETE RESTRICT,
  sortOrder INTEGER NOT NULL DEFAULT 0,
  UNIQUE(submitID,fileID)
);

CREATE TABLE IF NOT EXISTS QUIZZES (
  quizID TEXT PRIMARY KEY,
  classID TEXT NOT NULL REFERENCES CLASSES(classID) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT,
  durationMinutes INTEGER,
  maxScore REAL NOT NULL,
  randomQuestions INTEGER NOT NULL DEFAULT 0,
  randomChoices INTEGER NOT NULL DEFAULT 0,
  showAnswers INTEGER NOT NULL DEFAULT 0,
  maxAttempts INTEGER NOT NULL DEFAULT 1,
  passingPercent REAL NOT NULL DEFAULT 50,
  openAt TEXT,
  closeAt TEXT,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','open','closed','archived')),
  templateID TEXT,
  createdAt TEXT NOT NULL,
  updatedAt TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_quizzes_class_time ON QUIZZES(classID,openAt,closeAt,status);

CREATE TABLE IF NOT EXISTS QUIZ_QUESTIONS (
  questionID TEXT PRIMARY KEY,
  quizID TEXT NOT NULL REFERENCES QUIZZES(quizID) ON DELETE CASCADE,
  orderIndex INTEGER NOT NULL,
  questionType TEXT NOT NULL CHECK (questionType IN ('multiple_choice','multiple_answer','essay','matching','fill_blank')),
  questionText TEXT NOT NULL,
  choicesJSON TEXT,
  correctAnswerJSON TEXT,
  score REAL NOT NULL DEFAULT 1,
  imageFileID TEXT REFERENCES FILES(fileID) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_quiz_questions_order ON QUIZ_QUESTIONS(quizID,orderIndex);

CREATE TABLE IF NOT EXISTS QUIZ_RESULTS (
  resultID TEXT PRIMARY KEY,
  quizID TEXT NOT NULL REFERENCES QUIZZES(quizID) ON DELETE CASCADE,
  userID TEXT NOT NULL REFERENCES USERS(userID) ON DELETE CASCADE,
  score REAL NOT NULL DEFAULT 0,
  maxScore REAL NOT NULL DEFAULT 0,
  startedAt TEXT NOT NULL,
  submittedAt TEXT,
  answersJSON TEXT,
  status TEXT NOT NULL DEFAULT 'in_progress' CHECK (status IN ('in_progress','submitted','graded')),
  attemptNumber INTEGER NOT NULL,
  UNIQUE(quizID,userID,attemptNumber)
);
CREATE INDEX IF NOT EXISTS idx_quiz_results_user ON QUIZ_RESULTS(userID,submittedAt DESC);

CREATE TABLE IF NOT EXISTS SHOPS (
  shopID TEXT PRIMARY KEY,
  userID TEXT NOT NULL REFERENCES USERS(userID) ON DELETE CASCADE,
  ownerName TEXT NOT NULL,
  shopName TEXT NOT NULL,
  category TEXT,
  description TEXT,
  logoFileID TEXT REFERENCES FILES(fileID) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','suspended','closed')),
  shopRating REAL NOT NULL DEFAULT 0,
  createdAt TEXT NOT NULL,
  updatedAt TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS PRODUCTS (
  productID TEXT PRIMARY KEY,
  shopID TEXT NOT NULL REFERENCES SHOPS(shopID) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  priceTHB REAL,
  priceCoin INTEGER,
  stock INTEGER NOT NULL DEFAULT 0,
  category TEXT,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','active','paused','sold_out','deleted')),
  soldCount INTEGER NOT NULL DEFAULT 0,
  createdAt TEXT NOT NULL,
  updatedAt TEXT NOT NULL,
  promotionPrice REAL,
  promotionStart TEXT,
  promotionEnd TEXT
);
CREATE INDEX IF NOT EXISTS idx_products_shop_status ON PRODUCTS(shopID,status);

CREATE TABLE IF NOT EXISTS PRODUCT_FILES (
  productFileID TEXT PRIMARY KEY,
  productID TEXT NOT NULL REFERENCES PRODUCTS(productID) ON DELETE CASCADE,
  fileID TEXT NOT NULL REFERENCES FILES(fileID) ON DELETE RESTRICT,
  sortOrder INTEGER NOT NULL DEFAULT 0,
  UNIQUE(productID,fileID)
);

CREATE TABLE IF NOT EXISTS ORDERS (
  orderID TEXT PRIMARY KEY,
  productID TEXT NOT NULL REFERENCES PRODUCTS(productID) ON DELETE RESTRICT,
  shopID TEXT NOT NULL REFERENCES SHOPS(shopID) ON DELETE RESTRICT,
  buyerID TEXT NOT NULL REFERENCES USERS(userID) ON DELETE RESTRICT,
  quantity INTEGER NOT NULL,
  totalPrice REAL NOT NULL,
  currency TEXT NOT NULL CHECK (currency IN ('THB','COIN')),
  paymentMethod TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','confirmed','rejected','shipped','received','refunded','cancelled')),
  note TEXT,
  orderedAt TEXT NOT NULL,
  receivedAt TEXT,
  updatedAt TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_orders_buyer ON ORDERS(buyerID,orderedAt DESC);
CREATE INDEX IF NOT EXISTS idx_orders_shop ON ORDERS(shopID,orderedAt DESC);

CREATE TABLE IF NOT EXISTS REVIEWS (
  reviewID TEXT PRIMARY KEY,
  shopID TEXT NOT NULL REFERENCES SHOPS(shopID) ON DELETE CASCADE,
  productID TEXT NOT NULL REFERENCES PRODUCTS(productID) ON DELETE RESTRICT,
  orderID TEXT NOT NULL REFERENCES ORDERS(orderID) ON DELETE RESTRICT,
  userID TEXT NOT NULL REFERENCES USERS(userID) ON DELETE CASCADE,
  rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
  comment TEXT,
  reply TEXT,
  createdAt TEXT NOT NULL,
  repliedAt TEXT,
  UNIQUE(orderID,userID)
);

CREATE TABLE IF NOT EXISTS WALLETS (
  walletID TEXT PRIMARY KEY,
  userID TEXT NOT NULL UNIQUE REFERENCES USERS(userID) ON DELETE CASCADE,
  balanceTHB REAL NOT NULL DEFAULT 0,
  balanceCoin INTEGER NOT NULL DEFAULT 0,
  balanceVoucher INTEGER NOT NULL DEFAULT 0,
  dailySpendingLimit REAL,
  dailySpentTHB REAL NOT NULL DEFAULT 0,
  dailySpentDate TEXT,
  updatedAt TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS TRANSACTIONS (
  txID TEXT PRIMARY KEY,
  sourceUserID TEXT REFERENCES USERS(userID) ON DELETE SET NULL,
  destinationUserID TEXT REFERENCES USERS(userID) ON DELETE SET NULL,
  transactionType TEXT NOT NULL,
  currency TEXT NOT NULL CHECK (currency IN ('THB','COIN','VOUCHER')),
  amount REAL NOT NULL CHECK(amount >= 0),
  balanceBefore REAL,
  balanceAfter REAL,
  note TEXT,
  orderID TEXT REFERENCES ORDERS(orderID) ON DELETE SET NULL,
  referenceID TEXT,
  idempotencyKey TEXT UNIQUE,
  createdAt TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'completed'
);
CREATE INDEX IF NOT EXISTS idx_tx_source ON TRANSACTIONS(sourceUserID,createdAt DESC);
CREATE INDEX IF NOT EXISTS idx_tx_destination ON TRANSACTIONS(destinationUserID,createdAt DESC);

CREATE TABLE IF NOT EXISTS TOPUP_REQUESTS (
  requestID TEXT PRIMARY KEY,
  userID TEXT NOT NULL REFERENCES USERS(userID) ON DELETE CASCADE,
  amount REAL NOT NULL CHECK(amount > 0),
  slipFileID TEXT REFERENCES FILES(fileID) ON DELETE SET NULL,
  channel TEXT NOT NULL,
  approvedBy TEXT REFERENCES USERS(userID) ON DELETE SET NULL,
  requestedAt TEXT NOT NULL,
  approvedAt TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
  rejectionReason TEXT
);

CREATE TABLE IF NOT EXISTS ESCROW (
  escrowID TEXT PRIMARY KEY,
  orderID TEXT NOT NULL UNIQUE REFERENCES ORDERS(orderID) ON DELETE CASCADE,
  buyerID TEXT NOT NULL REFERENCES USERS(userID) ON DELETE RESTRICT,
  shopID TEXT NOT NULL REFERENCES SHOPS(shopID) ON DELETE RESTRICT,
  amount REAL NOT NULL,
  currency TEXT NOT NULL CHECK (currency IN ('THB','COIN')),
  status TEXT NOT NULL DEFAULT 'held' CHECK (status IN ('held','released','refunded')),
  createdAt TEXT NOT NULL,
  releasedAt TEXT,
  refundedAt TEXT
);

CREATE TABLE IF NOT EXISTS GAME_STATS (
  statID TEXT PRIMARY KEY,
  userID TEXT NOT NULL UNIQUE REFERENCES USERS(userID) ON DELETE CASCADE,
  totalXP INTEGER NOT NULL DEFAULT 0,
  level INTEGER NOT NULL DEFAULT 1,
  streak INTEGER NOT NULL DEFAULT 0,
  lastLoginDate TEXT,
  badgesJSON TEXT NOT NULL DEFAULT '[]',
  dailyQuestJSON TEXT NOT NULL DEFAULT '{}',
  season TEXT,
  updatedAt TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS XP_EVENTS (
  eventID TEXT PRIMARY KEY,
  userID TEXT NOT NULL REFERENCES USERS(userID) ON DELETE CASCADE,
  eventType TEXT NOT NULL,
  amount INTEGER NOT NULL,
  referenceID TEXT,
  createdAt TEXT NOT NULL,
  UNIQUE(userID,eventType,referenceID)
);
CREATE INDEX IF NOT EXISTS idx_xp_events_user ON XP_EVENTS(userID,createdAt DESC);

CREATE TABLE IF NOT EXISTS ACHIEVEMENTS (
  achieveID TEXT PRIMARY KEY,
  userID TEXT NOT NULL REFERENCES USERS(userID) ON DELETE CASCADE,
  badgeID TEXT NOT NULL,
  badgeType TEXT,
  awardedAt TEXT NOT NULL,
  note TEXT,
  UNIQUE(userID,badgeID)
);

CREATE TABLE IF NOT EXISTS BADGE_RULES (
  badgeID TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  icon TEXT,
  conditionJSON TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'active',
  createdAt TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS SEASONS (
  seasonID TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  academicYear TEXT,
  semester TEXT,
  startsAt TEXT NOT NULL,
  endsAt TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','active','closed')),
  createdAt TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS SEASON_RESULTS (
  resultID TEXT PRIMARY KEY,
  seasonID TEXT NOT NULL REFERENCES SEASONS(seasonID) ON DELETE CASCADE,
  userID TEXT NOT NULL REFERENCES USERS(userID) ON DELETE CASCADE,
  finalXP INTEGER NOT NULL,
  finalRank INTEGER,
  awardedTop3 INTEGER NOT NULL DEFAULT 0,
  createdAt TEXT NOT NULL,
  UNIQUE(seasonID,userID)
);

CREATE TABLE IF NOT EXISTS NOTIFICATIONS (
  notiID TEXT PRIMARY KEY,
  userID TEXT NOT NULL REFERENCES USERS(userID) ON DELETE CASCADE,
  type TEXT NOT NULL,
  title TEXT NOT NULL,
  content TEXT,
  targetURL TEXT,
  isRead INTEGER NOT NULL DEFAULT 0,
  createdAt TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON NOTIFICATIONS(userID,isRead,createdAt DESC);

CREATE TABLE IF NOT EXISTS EMAIL_LOGS (
  emailID TEXT PRIMARY KEY,
  userID TEXT REFERENCES USERS(userID) ON DELETE SET NULL,
  recipient TEXT NOT NULL,
  subject TEXT NOT NULL,
  content TEXT,
  status TEXT NOT NULL,
  createdAt TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS AUDIT_LOGS (
  logID TEXT PRIMARY KEY,
  userID TEXT REFERENCES USERS(userID) ON DELETE SET NULL,
  action TEXT NOT NULL,
  entityType TEXT,
  entityID TEXT,
  detailsJSON TEXT,
  ipHash TEXT,
  sessionReference TEXT,
  createdAt TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_time ON AUDIT_LOGS(createdAt DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user ON AUDIT_LOGS(userID,createdAt DESC);

CREATE TABLE IF NOT EXISTS SYSTEM_SETTINGS (
  settingKey TEXT PRIMARY KEY,
  settingValueJSON TEXT NOT NULL,
  updatedAt TEXT NOT NULL,
  updatedBy TEXT REFERENCES USERS(userID) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS PARENT_LINKS (
  linkID TEXT PRIMARY KEY,
  parentID TEXT NOT NULL REFERENCES USERS(userID) ON DELETE CASCADE,
  childID TEXT NOT NULL REFERENCES USERS(userID) ON DELETE CASCADE,
  createdAt TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
  UNIQUE(parentID,childID)
);
CREATE INDEX IF NOT EXISTS idx_parent_links_parent ON PARENT_LINKS(parentID,status);
CREATE INDEX IF NOT EXISTS idx_parent_links_child ON PARENT_LINKS(childID,status);

CREATE TABLE IF NOT EXISTS AUCTIONS (
  auctionID TEXT PRIMARY KEY,
  productID TEXT NOT NULL REFERENCES PRODUCTS(productID) ON DELETE RESTRICT,
  shopID TEXT NOT NULL REFERENCES SHOPS(shopID) ON DELETE RESTRICT,
  startPrice INTEGER NOT NULL,
  currentPrice INTEGER NOT NULL,
  highestBidderID TEXT REFERENCES USERS(userID) ON DELETE SET NULL,
  closesAt TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('draft','open','closed','cancelled')),
  createdAt TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auctions_close ON AUCTIONS(status,closesAt);

CREATE TABLE IF NOT EXISTS AUCTION_BIDS (
  bidID TEXT PRIMARY KEY,
  auctionID TEXT NOT NULL REFERENCES AUCTIONS(auctionID) ON DELETE CASCADE,
  userID TEXT NOT NULL REFERENCES USERS(userID) ON DELETE CASCADE,
  amount INTEGER NOT NULL,
  createdAt TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auction_bids ON AUCTION_BIDS(auctionID,amount DESC,createdAt ASC);
