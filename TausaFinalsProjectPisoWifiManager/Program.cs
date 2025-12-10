using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.IO;
using System.Text.RegularExpressions;

namespace FinalsProjectCompact
{
    // ═══════════════════════════════════════════════════════════
    // INTERFACES
    // ═══════════════════════════════════════════════════════════

    /// <summary>
    /// Represents an entity that can be authenticated with credentials
    /// </summary>
    public interface IAuthenticatable
    {
        string Username { get; }
        bool Authenticate(string password);
        string GetRole();
    }

    /// <summary>
    /// Represents an entity that can provide descriptions
    /// </summary>
    public interface IDescribable
    {
        string GetDescription();
        string GetDetailedInfo();
    }

    /// <summary>
    /// Represents an entity that can be validated
    /// </summary>
    public interface IValidatable
    {
        bool IsValid();
        IEnumerable<string> GetValidationErrors();
    }

    // ═══════════════════════════════════════════════════════════
    // CONSTANTS
    // ═══════════════════════════════════════════════════════════

    /// <summary>
    /// Application-wide constants
    /// </summary>
    public static class Constants
    {
        public const string CANCEL_KEYWORD = "cancel";
        public const string DATA_FILE = "pisowifi_data.json";

        // Username validation
        public const int USERNAME_MIN_LENGTH = 3;
        public const int USERNAME_MAX_LENGTH = 20;
        public const string USERNAME_PATTERN = @"^[a-z0-9]+$";

        // Password validation
        public const int PASSWORD_MIN_LENGTH = 4;
        public const int PASSWORD_MAX_LENGTH = 30;
    }

    // ═══════════════════════════════════════════════════════════
    // MODELS
    // ═══════════════════════════════════════════════════════════

    /// <summary>
    /// Base class 
    /// </summary>
    public abstract class Person : IAuthenticatable, IValidatable
    {
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";

        protected Person() { }

        protected Person(string username, string password)
        {
            Username = username;
            Password = password;
        }

        public abstract string GetRole();

        public virtual bool Authenticate(string password) => Password == password;

        public virtual bool IsValid() => !GetValidationErrors().Any();
        public static string NormalizeUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return string.Empty;

            return username.Trim().ToLower();
        }

        public static List<string> ValidateCredentials(string username, string password, bool normalizeUsername = true)
        {
            var errors = new List<string>();
            string normalized = normalizeUsername ? NormalizeUsername(username) : username;

            // Username validation
            if (normalized.Length < Constants.USERNAME_MIN_LENGTH)
                errors.Add($"Username must be at least {Constants.USERNAME_MIN_LENGTH} characters.");

            if (normalized.Length > Constants.USERNAME_MAX_LENGTH)
                errors.Add($"Username must not exceed {Constants.USERNAME_MAX_LENGTH} characters.");

            if (normalized.Contains(" "))
                errors.Add("Username cannot contain spaces.");

            if (!Regex.IsMatch(normalized, Constants.USERNAME_PATTERN))
                errors.Add("Username must be alphanumeric (letters and numbers only).");

            // Password validation
            if (password.Length < Constants.PASSWORD_MIN_LENGTH)
                errors.Add($"Password must be at least {Constants.PASSWORD_MIN_LENGTH} characters.");

            if (password.Length > Constants.PASSWORD_MAX_LENGTH)
                errors.Add($"Password must not exceed {Constants.PASSWORD_MAX_LENGTH} characters.");

            if (password.Contains(" "))
                errors.Add("Password cannot contain spaces.");

            return errors;
        }

        public virtual IEnumerable<string> GetValidationErrors()
        {
            return ValidateCredentials(Username, Password, normalizeUsername: false);
        }
    }

    /// <summary>
    /// le customer 
    /// </summary>
    public class User : Person
    {
        public List<Transaction> Transactions { get; set; } = new();

        public User() { }

        public User(string username, string password) : base(username, password) { }

        public override string GetRole() => "Customer";

        public decimal GetTotalSpent() => Transactions.Sum(t => t.Amount);

        public int GetTotalMinutesPurchased() => Transactions.Sum(t => t.Minutes);
    }

    /// <summary>
    /// le admin
    /// </summary>
    public class Admin : Person
    {
        public DateTime LastLogin { get; set; }

        public Admin() { }

        public Admin(string username, string password) : base(username, password) { }

        public override string GetRole() => "Administrator";

        public override bool Authenticate(string password)
        {
            bool success = base.Authenticate(password);
            if (success)
                LastLogin = DateTime.Now;
            return success;
        }
    }

    /// <summary>
    /// Transactions of the customerr
    /// </summary>
    public class Transaction : IDescribable, IValidatable
    {
        public string PackageName { get; set; } = "";
        public decimal Amount { get; set; }
        public int Minutes { get; set; }
        public DateTime DateTime { get; set; } = DateTime.Now;

        public Transaction() { }

        public Transaction(string packageName, decimal amount, int minutes)
        {
            PackageName = packageName;
            Amount = amount;
            Minutes = minutes;
            DateTime = DateTime.Now;
        }

        public string GetDescription() => $"{PackageName} - P{Amount}";

        public string GetDetailedInfo() =>
            $"{PackageName} - P{Amount} ({Minutes} mins) on {DateTime:yyyy-MM-dd HH:mm}";

        public bool IsValid() =>
            !string.IsNullOrWhiteSpace(PackageName) && Amount > 0 && Minutes > 0;

        public IEnumerable<string> GetValidationErrors()
        {
            var errors = new List<string>();

            if (string.IsNullOrWhiteSpace(PackageName))
                errors.Add("Package name cannot be empty");
            if (Amount <= 0)
                errors.Add("Amount must be greater than 0");
            if (Minutes <= 0)
                errors.Add("Minutes must be greater than 0");

            return errors;
        }
    }

    /// <summary>
    /// Active Wifi Session
    /// </summary>
    public class Session : IDescribable
    {
        public string Username { get; set; } = "";
        public string PackageName { get; set; } = "";
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }

        public Session() { }

        public Session(string username, string packageName, int minutes)
        {
            Username = username;
            PackageName = packageName;
            StartTime = DateTime.Now;
            EndTime = StartTime.AddMinutes(minutes);
        }

        public int GetRemainingMinutes()
        {
            var remaining = (EndTime - DateTime.Now).TotalMinutes;
            return (int)Math.Max(0, Math.Ceiling(remaining));
        }

        public bool IsActive() => DateTime.Now < EndTime;

        public string GetDescription() =>
            $"{Username} - {PackageName} ({GetRemainingMinutes()} mins left)";

        public string GetDetailedInfo() =>
            $"User: {Username} | Package: {PackageName} | " +
            $"Started: {StartTime:HH:mm:ss} | Expires: {EndTime:HH:mm:ss} | " +
            $"Remaining: {GetRemainingMinutes()} mins";
    }

    /// <summary>
    /// Packages or rates sa wifi
    /// </summary>
    public class WiFiPackage : IDescribable, IValidatable
    {
        public string Name { get; set; } = "";
        public int Minutes { get; set; }
        public decimal Price { get; set; }

        public WiFiPackage() { }

        public WiFiPackage(string name, int minutes, decimal price)
        {
            Name = name;
            Minutes = minutes;
            Price = price;
        }

        public string GetDescription() => $"{Name} - {Minutes} mins - P{Price}";

        public string GetDetailedInfo() =>
            $"{Name} | Duration: {Minutes} mins | Price: P{Price} | " +
            $"Rate: P{GetPricePerMinute():F3}/min";

        public decimal GetPricePerMinute() => Minutes > 0 ? Price / Minutes : 0;

        public bool IsValid() =>
            !string.IsNullOrWhiteSpace(Name) && Minutes > 0 && Price > 0;

        public IEnumerable<string> GetValidationErrors()
        {
            var errors = new List<string>();

            if (string.IsNullOrWhiteSpace(Name))
                errors.Add("Package name cannot be empty");
            if (Minutes <= 0)
                errors.Add("Minutes must be greater than 0");
            if (Price <= 0)
                errors.Add("Price must be greater than 0");

            return errors;
        }
    }

    // ═══════════════════════════════════════════════════════════
    // DATA TRANSFER OBJECTS
    // ═══════════════════════════════════════════════════════════

    /// <summary>
    /// Contains all system data for JSON serialization
    /// </summary>
    public class PisoWifiData
    {
        public List<User> Users { get; set; } = new();
        public List<Session> Sessions { get; set; } = new();
        public List<Transaction> AllTransactions { get; set; } = new();
        public Admin? AdminAccount { get; set; }
    }

    // ═══════════════════════════════════════════════════════════
    // SERVICES
    // ═══════════════════════════════════════════════════════════

    /// <summary>
    /// handles all le data
    /// </summary>
    public class DataService
    {
        private readonly List<User> _users = new();
        private readonly Dictionary<string, User> _usersByUsername;
        private readonly List<Session> _sessions = new();
        private readonly Dictionary<string, Session> _activeSessionsByUser;
        private readonly List<WiFiPackage> _packages;
        private readonly List<Transaction> _transactions = new();
        private Admin? _admin;

        public Admin? AdminAccount => _admin;

        public DataService()
        {
            _usersByUsername = new(StringComparer.OrdinalIgnoreCase);
            _activeSessionsByUser = new(StringComparer.OrdinalIgnoreCase);

            //WiFi packages
            _packages = new List<WiFiPackage>
            {
                new WiFiPackage("Quick Browse - 10 mins", 10, 1m),
                new WiFiPackage("Standard - 1 hour", 60, 5m),
                new WiFiPackage("Work Day - 8 hours", 480, 10m),
                new WiFiPackage("Extended - 12 hours", 720, 15m),
                new WiFiPackage("Full Day - 24 hours", 1440, 25m)
            };

            // admin credentials
            _admin = new Admin("adminFarah", "admin123");

            LoadFromFile(); //loads the file 
        }

        /// <summary>
        /// Loads all data from JSON file
        /// </summary>
        public void LoadFromFile()
        {
            try
            {
                if (!File.Exists(Constants.DATA_FILE)) //file name is "pisowifi_data.json" i made it a constant
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("[INFO] No existing data file found. Starting fresh.");
                    Console.ResetColor();
                    return;
                }

                string json = File.ReadAllText(Constants.DATA_FILE);

                if (string.IsNullOrWhiteSpace(json))
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("[WARNING] Data file is empty. Starting fresh.");
                    Console.ResetColor();
                    return;
                }

                var data = JsonSerializer.Deserialize<PisoWifiData>(json);

                if (data != null)
                {
                    _users.Clear();
                    _usersByUsername.Clear();
                    _sessions.Clear();
                    _activeSessionsByUser.Clear();
                    _transactions.Clear();

                    foreach (var user in data.Users)
                    {
                        user.Username = Person.NormalizeUsername(user.Username);
                        _users.Add(user);
                        _usersByUsername[user.Username] = user;
                    }

                    foreach (var session in data.Sessions.Where(s => s.IsActive()))
                    {
                        _sessions.Add(session);
                        _activeSessionsByUser[session.Username] = session;
                    }

                    _transactions.AddRange(data.AllTransactions);
                    _admin = data.AdminAccount;

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"[SUCCESS] Loaded successfully.");
                    Console.ResetColor();
                }
            }
            catch (JsonException ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[ERROR] Data file is corrupted: {ex.Message}");
                Console.WriteLine("[INFO] Starting with fresh data.");
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[ERROR] Error loading data: {ex.Message}");
                Console.ResetColor();
            }
        }

        /// <summary>
        /// Saves all data to JSON file
        /// </summary>
        public void SaveToFile()
        {
            try
            {
                CleanupExpiredSessions();

                var data = new PisoWifiData
                {
                    Users = _users,
                    Sessions = _sessions,
                    AllTransactions = _transactions,
                    AdminAccount = _admin
                };

                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    DefaultIgnoreCondition = JsonIgnoreCondition.Never
                };

                string json = JsonSerializer.Serialize(data, options);
                File.WriteAllText(Constants.DATA_FILE, json);
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[ERROR] Error saving data: {ex.Message}");
                Console.ResetColor();
            }
        }

        /// <summary>
        /// Removes expired sessions from memory
        /// </summary>
        private void CleanupExpiredSessions()
        {
            var expiredSessions = _sessions.Where(s => !s.IsActive()).ToList();

            foreach (var session in expiredSessions)
            {
                _sessions.Remove(session);
                _activeSessionsByUser.Remove(session.Username);
            }
        }

        public void SetAdmin(Admin admin)
        {
            if (admin == null)
                throw new ArgumentNullException(nameof(admin));

            _admin = admin;
            SaveToFile();
        }

        public void AddUser(User user)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (!user.IsValid())
                throw new InvalidOperationException(
                    string.Join(", ", user.GetValidationErrors()));

            // Normalize username before checking
            user.Username = User.NormalizeUsername(user.Username);

            if (_usersByUsername.ContainsKey(user.Username))
                throw new InvalidOperationException("Username already exists.");

            _users.Add(user);
            _usersByUsername[user.Username] = user;
            SaveToFile();
        }

        public bool UserExists(string username)
        {
            string normalized = Person.NormalizeUsername(username);
            return _usersByUsername.ContainsKey(normalized);
        }

        public User? AuthenticateUser(string username, string password)
        {
            string normalized = Person.NormalizeUsername(username);

            if (_usersByUsername.TryGetValue(normalized, out var user) &&
                user.Authenticate(password))
            {
                return user;
            }

            return null;
        }

        public IEnumerable<User> GetAllUsers() => _users.OrderBy(u => u.Username);

        public Session CreateSession(string username, string packageName, int minutes)
        {
            var session = new Session(username, packageName, minutes);
            _sessions.Add(session);
            _activeSessionsByUser[username] = session;
            SaveToFile();
            return session;
        }

        public Session? GetActiveSession(string username)
        {
            string normalized = User.NormalizeUsername(username);

            if (!_activeSessionsByUser.TryGetValue(normalized, out var session))
                return null;

            if (!session.IsActive())
            {
                _activeSessionsByUser.Remove(normalized);
                SaveToFile();
                return null;
            }

            return session;
        }

        public bool HasActiveSession(string username) =>
            GetActiveSession(username) != null;

        public IEnumerable<Session> GetActiveSessions() =>
            _activeSessionsByUser.Values.Where(s => s.IsActive()).ToList();

        public IReadOnlyList<WiFiPackage> GetAllPackages() => _packages.AsReadOnly();

        public WiFiPackage? GetPackage(int index) =>
            index >= 0 && index < _packages.Count ? _packages[index] : null;

        public Transaction CreateTransaction(WiFiPackage package)
        {
            if (package == null)
                throw new ArgumentNullException(nameof(package));

            var transaction = new Transaction(package.Name, package.Price, package.Minutes);
            _transactions.Add(transaction);
            return transaction;
        }

        public void AddTransactionToUser(User user, Transaction transaction)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (transaction == null)
                throw new ArgumentNullException(nameof(transaction));

            user.Transactions.Add(transaction);
            SaveToFile();
        }

        public decimal CalculateTotalRevenue() => _transactions.Sum(t => t.Amount);

        public decimal GetAverageTransactionValue() =>
            _transactions.Any() ? _transactions.Average(t => t.Amount) : 0;

        public Dictionary<string, (int Count, decimal Revenue)> GetRevenueByPackage() =>
            _transactions
                .GroupBy(t => t.PackageName)
                .ToDictionary(
                    g => g.Key,
                    g => (g.Count(), g.Sum(t => t.Amount))
                );
    }

    // ═══════════════════════════════════════════════════════════
    // USER INTERFACE
    // ═══════════════════════════════════════════════════════════

    /// <summary>
    /// Handles all menu interactions and user interface
    /// </summary>
    public class MenuHandler
    {
        private readonly DataService _data;

        public MenuHandler(DataService data)
        {
            _data = data ?? throw new ArgumentNullException(nameof(data));
        }

        /// <summary>
        /// Pauses execution until user presses a key
        /// </summary>
        public void Pause()
        {
            Console.WriteLine("\nPress any key to continue...");
            Console.ReadKey(true);
        }

        /// <summary>
        /// Reads a non-empty line from console
        /// </summary>
        public string ReadNonEmptyLine(string prompt)
        {
            while (true)
            {
                Console.Write(prompt);
                var input = Console.ReadLine();

                if (!string.IsNullOrWhiteSpace(input))
                    return input.Trim();

                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[ERROR] Input cannot be empty.");
                Console.ResetColor();
            }
        }

        /// <summary>
        /// Reads a line with cancel support - returns null if user types "cancel"
        /// </summary>
        public string? ReadLineWithCancel(string prompt)
        {
            while (true)
            {
                Console.Write(prompt);
                var input = Console.ReadLine();

                if (string.IsNullOrWhiteSpace(input))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[ERROR] Input cannot be empty.");
                    Console.ResetColor();
                    continue;
                }

                var trimmed = input.Trim();

                if (trimmed.Equals(Constants.CANCEL_KEYWORD, StringComparison.OrdinalIgnoreCase))
                    return null;

                return trimmed;
            }
        }

        /// <summary>
        /// Reads password with masking (shows asterisks) and toggle visibility
        /// Press Tab to toggle show/hide password
        /// </summary>
        public string? ReadPasswordWithMask(string prompt, bool allowCancel = true)
        {
            Console.Write(prompt);

            var password = new System.Text.StringBuilder();
            bool showPassword = false;

            while (true)
            {
                var key = Console.ReadKey(true);

                // Enter key - submit password
                if (key.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine();

                    if (password.Length == 0)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("[ERROR] Password cannot be empty.");
                        Console.ResetColor();
                        Console.Write(prompt);
                        continue;
                    }

                    string result = password.ToString();

                    // Check for cancel keyword
                    if (allowCancel && result.Equals(Constants.CANCEL_KEYWORD, StringComparison.OrdinalIgnoreCase))
                    {
                        return null;
                    }

                    return result;
                }
                // Backspace - delete last character
                else if (key.Key == ConsoleKey.Backspace)
                {
                    if (password.Length > 0)
                    {
                        password.Remove(password.Length - 1, 1);
                        Console.Write("\b \b"); // Erase last character from console
                    }
                }
                // Tab - toggle password visibility
                else if (key.Key == ConsoleKey.Tab)
                {
                    showPassword = !showPassword;

                    // Clear current line and rewrite password with new visibility
                    Console.Write("\r" + new string(' ', prompt.Length + password.Length + 20));
                    Console.Write("\r" + prompt);

                    if (showPassword)
                    {
                        Console.Write(password.ToString());
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.Write(" [VISIBLE]");
                        Console.ResetColor();
                    }
                    else
                    {
                        Console.Write(new string('*', password.Length));
                        Console.ForegroundColor = ConsoleColor.DarkGray;
                        Console.Write(" [HIDDEN]");
                        Console.ResetColor();
                    }
                }
                // Regular character - add to password
                else if (!char.IsControl(key.KeyChar))
                {
                    password.Append(key.KeyChar);

                    if (showPassword)
                    {
                        // Clear visibility indicator and rewrite
                        Console.Write("\r" + new string(' ', prompt.Length + password.Length + 20));
                        Console.Write("\r" + prompt + password.ToString());
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.Write(" [VISIBLE]");
                        Console.ResetColor();
                    }
                    else
                    {
                        Console.Write("*");
                    }
                }
            }
        }

        /// <summary>
        /// Reads an integer choice within specified range
        /// </summary>
        public int ReadChoice(string prompt, int min, int max)
        {
            while (true)
            {
                Console.Write(prompt);

                if (int.TryParse(Console.ReadLine(), out int value) &&
                    value >= min && value <= max)
                {
                    return value;
                }

                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[ERROR] Enter a number between {min} and {max}");
                Console.ResetColor();
            }
        }

        /// <summary>
        /// Reads a decimal value with cancel support
        /// </summary>
        private decimal? ReadDecimal(string prompt)
        {
            while (true)
            {
                Console.Write(prompt);
                string? input = Console.ReadLine();

                if (string.IsNullOrWhiteSpace(input) ||
                    input.Trim().Equals(Constants.CANCEL_KEYWORD, StringComparison.OrdinalIgnoreCase))
                {
                    return null;
                }

                if (decimal.TryParse(input, out decimal result))
                {
                    if (result <= 0)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("[ERROR] Payment must be greater than 0.");
                        Console.ResetColor();
                        continue;
                    }
                    return result;
                }

                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[ERROR] Invalid input. Enter a numeric value or type 'cancel'.");
                Console.ResetColor();
            }
        }

        /// <summary>
        /// Displays a formatted header
        /// </summary>
        public void ShowHeader(string title)
        {
            Console.Clear();
            Console.ForegroundColor = ConsoleColor.Cyan;

            string paddedTitle = title.Length > 29 ? title.Substring(0, 29) : title.PadRight(29);

            Console.WriteLine("╔══════════════════════════════════╗");
            Console.WriteLine($"║     {paddedTitle}║");
            Console.WriteLine("╚══════════════════════════════════╝");
            Console.ResetColor();
        }

        /// <summary>
        /// Handles user registration flow
        /// </summary>
        public void UserRegister()
        {
            ShowHeader("REGISTER");
            Console.WriteLine("Username requirements:");
            Console.WriteLine($" - {Constants.USERNAME_MIN_LENGTH}–{Constants.USERNAME_MAX_LENGTH} characters");
            Console.WriteLine(" - Alphanumeric only (no spaces or symbols)");
            Console.WriteLine($" - Type '{Constants.CANCEL_KEYWORD}' to cancel registration");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\nTIP: Press TAB to show/hide password while typing\n");
            Console.ResetColor();

            while (true)
            {
                string? rawUsername = ReadLineWithCancel("Username: ");
                if (rawUsername == null)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("[INFO] Registration canceled.");
                    Console.ResetColor();
                    Pause();
                    return;
                }

                string username = Person.NormalizeUsername(rawUsername);

                if (_data.UserExists(username))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[ERROR] Username already exists! Try another.");
                    Console.ResetColor();
                    continue;
                }

                string? password = ReadPasswordWithMask("Password: ");
                if (password == null)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("[INFO] Registration canceled.");
                    Console.ResetColor();
                    Pause();
                    return;
                }

                var validationErrors = Person.ValidateCredentials(username, password);
                if (validationErrors.Any())
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    foreach (var error in validationErrors)
                        Console.WriteLine($"[ERROR] {error}");
                    Console.ResetColor();
                    continue;
                }

                try
                {
                    var user = new User(username, password);
                    _data.AddUser(user);

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"[SUCCESS] Registration successful! Username saved as '{username}'");
                    Console.ResetColor();
                    Pause();
                    return;
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[ERROR] Registration failed: {ex.Message}");
                    Console.ResetColor();
                }
            }
        }

        /// <summary>
        /// Handles user login flow
        /// </summary>
        public User? UserLogin()
        {
            ShowHeader("USER LOGIN");
            Console.WriteLine($"Type '{Constants.CANCEL_KEYWORD}' at any time to go back");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("TIP: Press TAB to show/hide password while typing\n");
            Console.ResetColor();

            string? rawUsername = ReadLineWithCancel("Username: ");
            if (rawUsername == null)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[INFO] Login canceled.");
                Console.ResetColor();
                Pause();
                return null;
            }

            string username = User.NormalizeUsername(rawUsername);

            string? password = ReadPasswordWithMask("Password: ");
            if (password == null)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[INFO] Login canceled.");
                Console.ResetColor();
                Pause();
                return null;
            }

            var user = _data.AuthenticateUser(username, password);
            if (user == null)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[ERROR] Invalid credentials!");
                Console.ResetColor();
                Pause();
                return null;
            }

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[SUCCESS] Welcome back, {user.Username}!");
            Console.ResetColor();
            Pause();
            return user;
        }

        /// <summary>
        /// Displays the user menu and handles user actions
        /// </summary>
        public void ShowUserMenu(User user)
        {
            while (true)
            {
                ShowHeader($"USER MENU - {user.Username}");

                var activeSession = _data.GetActiveSession(user.Username);
                if (activeSession != null)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"[ACTIVE] Session: {activeSession.GetDescription()}\n");
                    Console.ResetColor();
                }

                Console.WriteLine("[1] Buy WiFi Package");
                Console.WriteLine("[2] View Active Session");
                Console.WriteLine("[3] View Transaction History");
                Console.WriteLine("[4] Logout\n");

                int choice = ReadChoice("Choice: ", 1, 4);

                switch (choice)
                {
                    case 1:
                        BuyPackage(user);
                        break;
                    case 2:
                        ViewSession(user);
                        break;
                    case 3:
                        ViewHistory(user);
                        break;
                    case 4:
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("[INFO] Logged out successfully.");
                        Console.ResetColor();
                        Pause();
                        return;
                }
            }
        }

        /// <summary>
        /// Handles WiFi package purchase flow
        /// </summary>
        private void BuyPackage(User user)
        {
            if (_data.HasActiveSession(user.Username))
            {
                var active = _data.GetActiveSession(user.Username);
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[WARNING] You already have an active session:");
                Console.WriteLine($"          {active?.PackageName} ({active?.GetRemainingMinutes()} mins left)");
                Console.ResetColor();
                Pause();
                return;
            }

            var packages = _data.GetAllPackages();

            Console.WriteLine("\nAvailable WiFi Packages:");
            Console.WriteLine("╔════╦════════════════════════╦════════╦═══════╗");
            Console.WriteLine("║ No ║ Package Name           ║ Minutes║ Price ║");
            Console.WriteLine("╠════╬════════════════════════╬════════╬═══════╣");

            for (int i = 0; i < packages.Count; i++)
            {
                var p = packages[i];
                Console.WriteLine($"║ {i + 1,-2} ║ {p.Name,-22} ║ {p.Minutes,6} ║ P{p.Price,4} ║");
            }

            Console.WriteLine("╚════╩════════════════════════╩════════╩═══════╝");
            Console.WriteLine("[0] Cancel\n");

            int choice = ReadChoice("Select package: ", 0, packages.Count);
            if (choice == 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[INFO] Purchase canceled.");
                Console.ResetColor();
                Pause();
                return;
            }

            var selected = _data.GetPackage(choice - 1);
            if (selected == null)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[ERROR] Invalid package selection.");
                Console.ResetColor();
                Pause();
                return;
            }

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"\n[INFO] {selected.GetDetailedInfo()}");
            Console.ResetColor();

            while (true)
            {
                decimal? payment = ReadDecimal($"Enter payment (P{selected.Price}) or type '{Constants.CANCEL_KEYWORD}': ");
                if (payment == null)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("[INFO] Purchase canceled.");
                    Console.ResetColor();
                    Pause();
                    return;
                }

                if (payment != selected.Price)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[ERROR] Incorrect amount. Please enter exactly P{selected.Price} or type '{Constants.CANCEL_KEYWORD}'.");
                    Console.ResetColor();
                    continue;
                }

                try
                {
                    var transaction = _data.CreateTransaction(selected);
                    _data.AddTransactionToUser(user, transaction);
                    var session = _data.CreateSession(user.Username, selected.Name, selected.Minutes);

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"\n[SUCCESS] Payment accepted! WiFi active for {selected.Minutes} mins!");
                    Console.WriteLine($"[INFO] Session expires at {session.EndTime:HH:mm:ss}");
                    Console.ResetColor();
                    Pause();
                    return;
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[ERROR] Transaction failed: {ex.Message}");
                    Console.ResetColor();
                    Pause();
                    return;
                }
            }
        }

        /// <summary>
        /// Displays active session details
        /// </summary>
        private void ViewSession(User user)
        {
            ShowHeader("ACTIVE SESSION");

            var session = _data.GetActiveSession(user.Username);

            if (session == null)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[WARNING] No active session.");
                Console.ResetColor();
            }
            else
            {
                Console.WriteLine("\n╔══════════════════════════════════════════════╗");
                Console.WriteLine("║         ACTIVE SESSION DETAILS               ║");
                Console.WriteLine("╠══════════════════════════════════════════════╣");
                Console.WriteLine($"║ User:      {session.Username.PadRight(34)}║");
                Console.WriteLine($"║ Package:   {session.PackageName.PadRight(34)}║");
                Console.WriteLine($"║ Started:   {session.StartTime:yyyy-MM-dd HH:mm:ss}               ║");
                Console.WriteLine($"║ Expires:   {session.EndTime:yyyy-MM-dd HH:mm:ss}               ║");
                Console.WriteLine($"║ Remaining: {session.GetRemainingMinutes()} minutes{new string(' ', 26 - session.GetRemainingMinutes().ToString().Length)}║");
                Console.WriteLine("╚══════════════════════════════════════════════╝");
            }

            Pause();
        }

        /// <summary>
        /// Displays transaction history for a user
        /// </summary>
        private void ViewHistory(User user)
        {
            ShowHeader("TRANSACTION HISTORY");

            if (!user.Transactions.Any())
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[WARNING] No transactions yet.");
                Console.ResetColor();
                Pause();
                return;
            }

            Console.WriteLine("\n╔══════════════════════════════╦════════╦═════════╦═════════════════════╗");
            Console.WriteLine("║ Package Name                 ║ Amount ║ Minutes ║ Date & Time         ║");
            Console.WriteLine("╠══════════════════════════════╬════════╬═════════╬═════════════════════╣");

            foreach (var t in user.Transactions.OrderByDescending(x => x.DateTime))
            {
                Console.WriteLine($"║ {t.PackageName,-28} ║ P{t.Amount,5} ║ {t.Minutes,7} ║ {t.DateTime:yyyy-MM-dd HH:mm}    ║");
            }

            Console.WriteLine("╚══════════════════════════════╩════════╩═════════╩═════════════════════╝");

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"\n[SUMMARY] Total Spent: P{user.GetTotalSpent():F2}");
            Console.WriteLine($"[SUMMARY] Total Minutes Purchased: {user.GetTotalMinutesPurchased()} mins");
            Console.WriteLine($"[SUMMARY] Total Transactions: {user.Transactions.Count}");
            Console.ResetColor();

            Pause();
        }

        /// <summary>
        /// Handles admin login flow
        /// </summary>
        public Admin? AdminLogin()
        {
            ShowHeader("ADMIN LOGIN");
            Console.WriteLine($"Type '{Constants.CANCEL_KEYWORD}' at any time to go back");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("TIP: Press TAB to show/hide password while typing\n");
            Console.ResetColor();

            string? username = ReadLineWithCancel("Username: ");
            if (username == null)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[INFO] Login canceled.");
                Console.ResetColor();
                Pause();
                return null;
            }

            string? password = ReadPasswordWithMask("Password: ");
            if (password == null)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[INFO] Login canceled.");
                Console.ResetColor();
                Pause();
                return null;
            }

            var admin = _data.AdminAccount;
            if (admin != null &&
                admin.Username.Equals(username, StringComparison.OrdinalIgnoreCase) &&
                admin.Authenticate(password))
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[SUCCESS] Welcome Admin, {admin.Username}!");
                Console.WriteLine($"[INFO] Last login: {admin.LastLogin:yyyy-MM-dd HH:mm:ss}");
                Console.ResetColor();
                Pause();
                return admin;
            }

            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[ERROR] Invalid admin credentials!");
            Console.ResetColor();
            Pause();
            return null;
        }

        /// <summary>
        /// Displays admin menu and handles admin actions
        /// </summary>
        public void ShowAdminMenu(Admin admin)
        {
            while (true)
            {
                ShowHeader($"ADMIN MENU - {admin.Username}");

                // Display last login info
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"Last Login: {admin.LastLogin:yyyy-MM-dd HH:mm:ss}");
                Console.ResetColor();
                Console.WriteLine();

                Console.WriteLine("[1] View All Users & Transactions");
                Console.WriteLine("[2] View Active Sessions");
                Console.WriteLine("[3] Revenue Report");
                Console.WriteLine("[4] Logout\n");

                int choice = ReadChoice("Choice: ", 1, 4);

                switch (choice)
                {
                    case 1:
                        ShowUsersAndTransactions();
                        break;
                    case 2:
                        ShowActiveSessions();
                        break;
                    case 3:
                        ShowRevenueReport();
                        break;
                    case 4:
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("[INFO] Admin logged out successfully.");
                        Console.ResetColor();
                        Pause();
                        return;
                }
            }
        }

        /// <summary>
        /// Displays all users and their transactions
        /// </summary>
        private void ShowUsersAndTransactions()
        {
            ShowHeader("USERS & TRANSACTIONS");

            var users = _data.GetAllUsers().ToList();

            if (!users.Any())
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[WARNING] No registered users yet.");
                Console.ResetColor();
                Pause();
                return;
            }

            foreach (var u in users)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"\n[USER] {u.Username}");
                Console.WriteLine($"       Total Spent: P{u.GetTotalSpent():F2} | " +
                                $"Total Minutes: {u.GetTotalMinutesPurchased()} | " +
                                $"Transactions: {u.Transactions.Count}");
                Console.ResetColor();

                if (!u.Transactions.Any())
                {
                    Console.WriteLine("       No transactions.");
                }
                else
                {
                    Console.WriteLine("       ┌────────────────────────┬────────┬─────────┬─────────────────────┐");
                    Console.WriteLine("       │ Package                │ Amount │ Minutes │ Date & Time         │");
                    Console.WriteLine("       ├────────────────────────┼────────┼─────────┼─────────────────────┤");

                    foreach (var t in u.Transactions.OrderByDescending(x => x.DateTime))
                    {
                        Console.WriteLine($"       │ {t.PackageName,-22} │ P{t.Amount,5} │ {t.Minutes,7} │ {t.DateTime:yyyy-MM-dd HH:mm}    │");
                    }

                    Console.WriteLine("       └────────────────────────┴────────┴─────────┴─────────────────────┘");
                }
            }

            Pause();
        }

        /// <summary>
        /// Displays all active sessions
        /// </summary>
        private void ShowActiveSessions()
        {
            ShowHeader("ACTIVE SESSIONS");

            var sessions = _data.GetActiveSessions().OrderBy(s => s.GetRemainingMinutes()).ToList();

            if (!sessions.Any())
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[WARNING] No active sessions.");
                Console.ResetColor();
                Pause();
                return;
            }

            Console.WriteLine("\n╔════════════════╦══════════════════════════╦═══════════╦═══════════╦═══════════╗");
            Console.WriteLine("║ Username       ║ Package                  ║ Started   ║ Expires   ║ Remaining ║");
            Console.WriteLine("╠════════════════╬══════════════════════════╬═══════════╬═══════════╬═══════════╣");

            foreach (var s in sessions)
            {
                Console.WriteLine($"║ {s.Username,-14} ║ {s.PackageName,-24} ║ {s.StartTime:HH:mm:ss}  ║ {s.EndTime:HH:mm:ss}  ║ {s.GetRemainingMinutes(),6} m  ║");
            }
            Console.WriteLine("╚════════════════╩══════════════════════════╩═══════════╩═══════════╩═══════════╝");

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"\n[SUMMARY] Total Active Sessions: {sessions.Count}");
            Console.WriteLine($"[SUMMARY] Total Active Users: {sessions.Select(s => s.Username).Distinct().Count()}");
            Console.ResetColor();

            Pause();
        }

        /// <summary>
        /// Displays revenue report
        /// </summary>
        private void ShowRevenueReport()
        {
            ShowHeader("REVENUE REPORT");

            decimal totalRevenue = _data.CalculateTotalRevenue();
            decimal avgTransaction = _data.GetAverageTransactionValue();
            var byPackage = _data.GetRevenueByPackage();

            Console.WriteLine("\n╔════════════════════════════════════════════╗");
            Console.WriteLine("║         FINANCIAL SUMMARY                  ║");
            Console.WriteLine("╠════════════════════════════════════════════╣");

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"║ Total Revenue:        P{totalRevenue,17:F2}   ║");
            Console.ResetColor();
            Console.WriteLine($"║ Average Transaction:  P{avgTransaction,17:F2}   ║");
            Console.WriteLine("╚════════════════════════════════════════════╝");

            if (byPackage.Any())
            {
                Console.WriteLine("\n╔══════════════════════════════╦═════════╦════════════╗");
                Console.WriteLine("║ Package Name                 ║ Sales   ║ Revenue    ║");
                Console.WriteLine("╠══════════════════════════════╬═════════╬════════════╣");

                foreach (var kv in byPackage.OrderByDescending(x => x.Value.Revenue))
                {
                    Console.WriteLine($"║ {kv.Key,-28} ║ {kv.Value.Count,7} ║ P{kv.Value.Revenue,9:F2} ║");
                }

                Console.WriteLine("╚══════════════════════════════╩═════════╩════════════╝");

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"\n[SUMMARY] Total Sales: {byPackage.Sum(x => x.Value.Count)}");
                Console.WriteLine($"[SUMMARY] Best Seller: {byPackage.OrderByDescending(x => x.Value.Count).First().Key}");
                Console.WriteLine($"[SUMMARY] Highest Revenue: {byPackage.OrderByDescending(x => x.Value.Revenue).First().Key}");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("\n[WARNING] No transactions recorded yet.");
                Console.ResetColor();
            }

            Pause();
        }
    }

    // ═══════════════════════════════════════════════════════════
    // MAIN PROGRAM
    // ═══════════════════════════════════════════════════════════

    /// <summary>
    /// Main program entry point
    /// </summary>
    public class Program
    {
        static void Main()
        {
            try
            {
                Console.OutputEncoding = System.Text.Encoding.UTF8;

                var data = new DataService();
                var menu = new MenuHandler(data);

                // Display welcome banner
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("╔════════════════════════════════════════╗");
                Console.WriteLine("║       PisoWifi Management System       ║");
                Console.WriteLine("╚════════════════════════════════════════╝");
                Console.ResetColor();
                Console.WriteLine("\nInitializing system...");
                System.Threading.Thread.Sleep(500);

                // Main program loop
                while (true)
                {
                    menu.ShowHeader("MAIN MENU");
                    Console.WriteLine("[1] Register");
                    Console.WriteLine("[2] Login as User");
                    Console.WriteLine("[3] Login as Admin");
                    Console.WriteLine("[4] Exit\n");

                    int choice = menu.ReadChoice("Choice: ", 1, 4);

                    switch (choice)
                    {
                        case 1:
                            menu.UserRegister();
                            break;

                        case 2:
                            var user = menu.UserLogin();
                            if (user != null)
                                menu.ShowUserMenu(user);
                            break;

                        case 3:
                            var loggedAdmin = menu.AdminLogin();
                            if (loggedAdmin != null)
                                menu.ShowAdminMenu(loggedAdmin);
                            break;

                        case 4:
                            Console.ForegroundColor = ConsoleColor.Cyan;
                            Console.WriteLine("\n╔════════════════════════════════════════╗");
                            Console.WriteLine("║      Thank you for using PisoWifi!     ║");
                            Console.WriteLine("║               Goodbye!                 ║");
                            Console.WriteLine("╚════════════════════════════════════════╝");
                            Console.ResetColor();
                            data.SaveToFile();
                            return;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\n[FATAL ERROR] Application crashed: {ex.Message}");
                Console.WriteLine($"Stack Trace: {ex.StackTrace}");
                Console.ResetColor();
                Console.WriteLine("\nPress any key to exit...");
                Console.ReadKey();
            }
        }
    }
}