# Refactoring Patterns Reference Guide

Detailed patterns and examples for common refactoring scenarios. Reference this when you need specific guidance on HOW to refactor.

---

## File Size Reduction Patterns

### Pattern 1: Extract Types Module

**Before:** Large file with many type definitions mixed with logic

**After:** Create `types.rs` with all type definitions

```rust
// types.rs
pub struct Config { /* ... */ }
pub struct Request { /* ... */ }
pub struct Response { /* ... */ }
pub enum Status { /* ... */ }

// main.rs or service.rs
use crate::types::*;
// Logic only, no type definitions
```

**When to use:** File has >10 struct/enum definitions

---

### Pattern 2: Extract Error Module

**Before:** Error types scattered or inline with logic

**After:** Create `errors.rs` with all error types

```rust
// errors.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("validation failed: {0}")]
    Validation(String),
}

pub type Result<T> = std::result::Result<T, ServiceError>;
```

**When to use:** Multiple error types or complex error handling

---

### Pattern 3: Split by Feature

**Before:** One large file with multiple features

**After:** Submodule per feature

```
// Before: service.rs (800 lines)

// After:
service/
  mod.rs          (exports & shared utilities)
  auth.rs         (authentication logic)
  validation.rs   (validation logic)
  storage.rs      (storage operations)
  helpers.rs      (internal helpers)
```

**When to use:** File has distinct feature groups that can work independently

---

### Pattern 4: Extract Helper Functions

**Before:** Many small utility functions in main file

**After:** Create `helpers.rs` or `utils.rs`

```rust
// helpers.rs (private utilities)
pub(crate) fn parse_id(s: &str) -> Result<u64> { /* ... */ }
pub(crate) fn format_timestamp(ts: i64) -> String { /* ... */ }
pub(crate) fn sanitize_input(input: &str) -> String { /* ... */ }
```

**When to use:** Many small functions that support main logic

---

## Function Length Reduction Patterns

### Pattern 1: Extract Validation

**Before:**
```rust
pub fn process_request(req: Request) -> Result<Response> {
    // 20 lines of validation
    if req.id.is_empty() { return Err(...); }
    if req.amount < 0 { return Err(...); }
    if req.user_id.len() != 32 { return Err(...); }
    // ... more validation
    
    // 30 lines of processing
    // ...
}
```

**After:**
```rust
pub fn process_request(req: Request) -> Result<Response> {
    validate_request(&req)?;
    execute_request(req)
}

fn validate_request(req: &Request) -> Result<()> {
    if req.id.is_empty() {
        return Err(Error::Validation("id cannot be empty".into()));
    }
    if req.amount < 0 {
        return Err(Error::Validation("amount must be positive".into()));
    }
    if req.user_id.len() != 32 {
        return Err(Error::Validation("invalid user_id length".into()));
    }
    Ok(())
}

fn execute_request(req: Request) -> Result<Response> {
    // Processing logic only
}
```

---

### Pattern 2: Extract Phase Functions

**Before:**
```rust
pub fn complex_operation(input: Input) -> Result<Output> {
    // 15 lines: prepare data
    // 20 lines: execute operation  
    // 15 lines: finalize and cleanup
}
```

**After:**
```rust
pub fn complex_operation(input: Input) -> Result<Output> {
    let prepared = prepare_operation(input)?;
    let executed = execute_operation(prepared)?;
    finalize_operation(executed)
}

fn prepare_operation(input: Input) -> Result<PreparedData> {
    // Preparation logic
}

fn execute_operation(data: PreparedData) -> Result<ExecutedData> {
    // Core logic
}

fn finalize_operation(data: ExecutedData) -> Result<Output> {
    // Finalization logic
}
```

---

### Pattern 3: Extract Conditionals

**Before:**
```rust
pub fn should_process(req: &Request) -> bool {
    req.is_valid() 
        && req.user.is_authenticated() 
        && req.permissions.contains(&Permission::Write)
        && !req.is_expired()
        && req.rate_limit.check().is_ok()
}
```

**After:**
```rust
pub fn should_process(req: &Request) -> bool {
    is_valid_request(req) && has_required_permissions(req) && is_within_limits(req)
}

fn is_valid_request(req: &Request) -> bool {
    req.is_valid() && !req.is_expired()
}

fn has_required_permissions(req: &Request) -> bool {
    req.user.is_authenticated() && req.permissions.contains(&Permission::Write)
}

fn is_within_limits(req: &Request) -> bool {
    req.rate_limit.check().is_ok()
}
```

---

### Pattern 4: Reduce Nesting with Early Returns

**Before:**
```rust
fn process(data: Data) -> Result<Output> {
    if data.is_valid() {
        if let Some(user) = data.get_user() {
            if user.has_permission() {
                // Deep nested logic here
                Ok(result)
            } else {
                Err(Error::NoPermission)
            }
        } else {
            Err(Error::UserNotFound)
        }
    } else {
        Err(Error::InvalidData)
    }
}
```

**After:**
```rust
fn process(data: Data) -> Result<Output> {
    if !data.is_valid() {
        return Err(Error::InvalidData);
    }
    
    let user = data.get_user().ok_or(Error::UserNotFound)?;
    
    if !user.has_permission() {
        return Err(Error::NoPermission);
    }
    
    // Logic at top level (no nesting)
    Ok(result)
}
```

---

## Code Duplication Elimination Patterns

### Pattern 1: Extract Common Function

**Before:** Same logic in multiple places
```rust
// In file A
let hash = Sha256::digest(&data);
let hex = hex::encode(hash);
store.save(&hex, &data)?;

// In file B  
let hash = Sha256::digest(&other_data);
let hex = hex::encode(hash);
cache.insert(&hex, &other_data)?;
```

**After:**
```rust
// In utils.rs or helpers.rs
fn compute_hash_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    hex::encode(hash)
}

// In file A
let hex = compute_hash_hex(&data);
store.save(&hex, &data)?;

// In file B
let hex = compute_hash_hex(&other_data);
cache.insert(&hex, &other_data)?;
```

---

### Pattern 2: Use Traits for Common Behavior

**Before:** Similar methods on multiple types
```rust
impl UserStore {
    pub fn get_by_id(&self, id: &str) -> Result<User> { /* ... */ }
}

impl SessionStore {
    pub fn get_by_id(&self, id: &str) -> Result<Session> { /* ... */ }
}

impl TokenStore {
    pub fn get_by_id(&self, id: &str) -> Result<Token> { /* ... */ }
}
```

**After:**
```rust
pub trait Store<T> {
    fn get_by_id(&self, id: &str) -> Result<T>;
    fn save(&self, id: &str, item: &T) -> Result<()>;
    fn delete(&self, id: &str) -> Result<()>;
}

impl Store<User> for UserStore { /* ... */ }
impl Store<Session> for SessionStore { /* ... */ }
impl Store<Token> for TokenStore { /* ... */ }
```

---

### Pattern 3: Generic Functions

**Before:** Type-specific functions with identical logic
```rust
fn validate_user_input(input: &UserInput) -> Result<()> {
    if input.id.is_empty() { return Err(...); }
    if input.name.len() > 255 { return Err(...); }
    Ok(())
}

fn validate_session_input(input: &SessionInput) -> Result<()> {
    if input.id.is_empty() { return Err(...); }
    if input.token.len() > 255 { return Err(...); }
    Ok(())
}
```

**After:**
```rust
trait Validatable {
    fn validate(&self) -> Result<()>;
}

fn validate_input<T: Validatable>(input: &T) -> Result<()> {
    input.validate()
}

impl Validatable for UserInput {
    fn validate(&self) -> Result<()> {
        if self.id.is_empty() { return Err(...); }
        if self.name.len() > 255 { return Err(...); }
        Ok(())
    }
}
```

---

### Pattern 4: Builder Pattern for Complex Construction

**Before:** Duplicated construction logic
```rust
// In multiple places:
let config = Config {
    host: "localhost".to_string(),
    port: 8080,
    timeout: Duration::from_secs(30),
    retries: 3,
    tls_enabled: true,
    // ... many more fields
};
```

**After:**
```rust
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    pub fn new() -> Self {
        Self { config: Config::default() }
    }
    
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.config.host = host.into();
        self
    }
    
    pub fn port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }
    
    pub fn build(self) -> Config {
        self.config
    }
}

// Usage:
let config = ConfigBuilder::new()
    .host("localhost")
    .port(8080)
    .build();
```

---

## Complexity Reduction Patterns

### Pattern 1: Replace Complex Match with Helper

**Before:**
```rust
match (req.method, req.auth, req.permission) {
    (Method::Get, Some(auth), perm) if perm.allows_read() && auth.is_valid() => { /* ... */ },
    (Method::Post, Some(auth), perm) if perm.allows_write() && auth.is_valid() => { /* ... */ },
    (Method::Delete, Some(auth), perm) if perm.allows_delete() && auth.is_admin() => { /* ... */ },
    _ => return Err(Error::Unauthorized),
}
```

**After:**
```rust
if !is_authorized(&req) {
    return Err(Error::Unauthorized);
}

match req.method {
    Method::Get => handle_get(req),
    Method::Post => handle_post(req),
    Method::Delete => handle_delete(req),
    _ => Err(Error::MethodNotAllowed),
}

fn is_authorized(req: &Request) -> bool {
    let Some(auth) = &req.auth else { return false };
    
    match req.method {
        Method::Get => req.permission.allows_read() && auth.is_valid(),
        Method::Post => req.permission.allows_write() && auth.is_valid(),
        Method::Delete => req.permission.allows_delete() && auth.is_admin(),
        _ => false,
    }
}
```

---

### Pattern 2: Group Parameters into Struct

**Before:**
```rust
pub fn create_user(
    name: String,
    email: String,
    age: u32,
    address: String,
    phone: String,
    role: Role,
    department: String,
) -> Result<User>
```

**After:**
```rust
pub struct CreateUserRequest {
    pub name: String,
    pub email: String,
    pub age: u32,
    pub address: String,
    pub phone: String,
    pub role: Role,
    pub department: String,
}

pub fn create_user(req: CreateUserRequest) -> Result<User>
```

---

### Pattern 3: Split Long Iterator Chains

**Before:**
```rust
let result = items
    .iter()
    .filter(|x| x.is_active())
    .filter(|x| x.amount > 100)
    .map(|x| x.transform())
    .filter_map(|x| x.validate().ok())
    .map(|x| x.normalize())
    .collect::<Vec<_>>();
```

**After:**
```rust
fn is_eligible(item: &Item) -> bool {
    item.is_active() && item.amount > 100
}

fn process_item(item: &Item) -> Option<ProcessedItem> {
    item.transform()
        .validate()
        .ok()
        .map(|x| x.normalize())
}

let result = items
    .iter()
    .filter(|x| is_eligible(x))
    .filter_map(|x| process_item(x))
    .collect();
```

---

## Error Handling Patterns

### Pattern 1: Add Context at Boundaries

**Before:**
```rust
let data = read_file(path)?;
let parsed = parse_data(&data)?;
let validated = validate(&parsed)?;
```

**After:**
```rust
use anyhow::Context;

let data = read_file(path)
    .context(format!("failed to read file: {}", path.display()))?;
    
let parsed = parse_data(&data)
    .context("failed to parse data")?;
    
let validated = validate(&parsed)
    .context(format!("validation failed for id: {}", parsed.id))?;
```

---

### Pattern 2: Custom Error with Context

**Before:**
```rust
#[derive(Error, Debug)]
pub enum Error {
    #[error("not found")]
    NotFound,
}
```

**After:**
```rust
#[derive(Error, Debug)]
pub enum Error {
    #[error("item not found: {item_type} with id {id}")]
    NotFound {
        item_type: String,
        id: String,
    },
}

// Usage:
return Err(Error::NotFound {
    item_type: "User".to_string(),
    id: user_id.clone(),
});
```

---

## Testing After Refactoring

### Pattern 1: Test Extracted Functions

When you extract a function, add a test:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_request_valid() {
        let req = Request {
            id: "123".into(),
            amount: 100,
            user_id: "a".repeat(32),
        };
        assert!(validate_request(&req).is_ok());
    }

    #[test]
    fn test_validate_request_empty_id() {
        let req = Request {
            id: "".into(),
            amount: 100,
            user_id: "a".repeat(32),
        };
        assert!(validate_request(&req).is_err());
    }
}
```

---

### Pattern 2: Preserve Behavior Tests

Before refactoring, add a high-level test to ensure behavior doesn't change:

```rust
#[test]
fn test_process_request_integration() {
    // Test the full function behavior before refactoring
    let req = create_test_request();
    let result = process_request(req).unwrap();
    assert_eq!(result.status, Status::Success);
    // After refactoring, this test should still pass
}
```

---

## When NOT to Refactor

### Anti-Pattern 1: Arbitrary Splitting
❌ Don't split files just to meet line counts if it harms cohesion
✅ Do split along logical boundaries

### Anti-Pattern 2: Over-Abstraction
❌ Don't create traits/generics for 2 similar functions
✅ Do wait for 3+ instances before abstracting

### Anti-Pattern 3: Premature Optimization
❌ Don't optimize for performance during refactoring
✅ Do optimize for readability and maintainability

### Anti-Pattern 4: Breaking Public APIs
❌ Don't change public function signatures without deprecation
✅ Do use `#[deprecated]` and provide migration path

---

## Quick Decision Tree

**File > 500 lines?**
- Has distinct features? → Split by feature (Pattern 3)
- Many types? → Extract types.rs (Pattern 1)
- Many errors? → Extract errors.rs (Pattern 2)
- Many helpers? → Extract helpers.rs (Pattern 4)

**Function > 50 lines?**
- Has validation? → Extract validation (Pattern 1)
- Has phases? → Extract phase functions (Pattern 2)
- Deep nesting? → Use early returns (Pattern 4)
- Complex conditionals? → Extract conditionals (Pattern 3)

**Code duplication?**
- Same file? → Extract function (Pattern 1)
- Similar behavior? → Use trait (Pattern 2)
- Type-specific? → Use generics (Pattern 3)
- Complex construction? → Builder pattern (Pattern 4)

**Too complex?**
- Complex match? → Extract helpers (Pattern 1)
- Many params? → Group into struct (Pattern 2)
- Long chains? → Split with intermediate functions (Pattern 3)

---

**Remember:** Always test after each change. Refactoring should never change behavior.
