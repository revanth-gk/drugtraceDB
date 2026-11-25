"""MySQL 8 schema for DrugTrace.

Each entry in STATEMENTS is sent to MySQL as one statement, so the compound
`CREATE PROCEDURE` body does not need the mysql CLI's DELIMITER directive.
"""

from __future__ import annotations

STATEMENTS: list[str] = [
    """
    CREATE TABLE manufacturer (
      manufacturer_id INT AUTO_INCREMENT PRIMARY KEY,
      name            VARCHAR(150) NOT NULL,
      licence_no      VARCHAR(40)  NOT NULL UNIQUE
    ) ENGINE=InnoDB
    """,
    """
    CREATE TABLE medicine_product (
      product_id      INT AUTO_INCREMENT PRIMARY KEY,
      manufacturer_id INT NOT NULL,
      brand_name      VARCHAR(100) NOT NULL,
      generic_name    VARCHAR(100) NOT NULL,
      strength        VARCHAR(30)  NOT NULL,
      dosage_form     ENUM('TABLET','CAPSULE','SYRUP','INJECTION','OINTMENT','OTHER') NOT NULL,
      UNIQUE (manufacturer_id, brand_name, strength),
      CONSTRAINT fk_product_manufacturer
        FOREIGN KEY (manufacturer_id) REFERENCES manufacturer(manufacturer_id)
    ) ENGINE=InnoDB
    """,
    """
    CREATE TABLE medicine_batch (
      batch_id    INT AUTO_INCREMENT PRIMARY KEY,
      product_id  INT NOT NULL,
      batch_no    VARCHAR(40) NOT NULL,
      mfg_date    DATE NOT NULL,
      expiry_date DATE NOT NULL,
      UNIQUE (product_id, batch_no),
      CONSTRAINT chk_batch_dates CHECK (mfg_date < expiry_date),
      CONSTRAINT fk_batch_product
        FOREIGN KEY (product_id) REFERENCES medicine_product(product_id)
    ) ENGINE=InnoDB
    """,
    """
    CREATE TABLE supply_org (
      org_id   INT AUTO_INCREMENT PRIMARY KEY,
      org_name VARCHAR(150) NOT NULL UNIQUE,
      org_type ENUM('DISTRIBUTOR','WHOLESALER','PHARMACY_CHAIN','MANUFACTURER_DEPOT') NOT NULL
    ) ENGINE=InnoDB
    """,
    """
    CREATE TABLE facility (
      facility_id   INT AUTO_INCREMENT PRIMARY KEY,
      org_id        INT NOT NULL,
      facility_name VARCHAR(150) NOT NULL,
      facility_type ENUM('WAREHOUSE','PHARMACY') NOT NULL,
      district      VARCHAR(80) NOT NULL,
      CONSTRAINT fk_facility_org
        FOREIGN KEY (org_id) REFERENCES supply_org(org_id)
    ) ENGINE=InnoDB
    """,
    """
    CREATE TABLE app_user (
      user_id       INT AUTO_INCREMENT PRIMARY KEY,
      username      VARCHAR(50) NOT NULL UNIQUE,
      password_hash VARCHAR(100) NOT NULL,
      role          ENUM('OPERATOR','RECALL_OFFICER','VIEWER') NOT NULL
    ) ENGINE=InnoDB
    """,
    """
    CREATE TABLE stock_movement (
      movement_id      INT AUTO_INCREMENT PRIMARY KEY,
      batch_id         INT NOT NULL,
      from_facility_id INT NULL,
      to_facility_id   INT NULL,
      movement_type    ENUM('INITIAL_RECEIPT','TRANSFER','RETURN','DAMAGE','EXPIRY') NOT NULL,
      quantity         INT NOT NULL,
      movement_date    DATE NOT NULL,
      reference_no     VARCHAR(40) NOT NULL UNIQUE,
      recorded_by      INT NOT NULL,
      CONSTRAINT chk_qty CHECK (quantity > 0),
      CONSTRAINT chk_pattern CHECK (
           (movement_type = 'INITIAL_RECEIPT' AND from_facility_id IS NULL AND to_facility_id IS NOT NULL)
        OR (movement_type IN ('TRANSFER','RETURN') AND from_facility_id IS NOT NULL
            AND to_facility_id IS NOT NULL AND from_facility_id <> to_facility_id)
        OR (movement_type IN ('DAMAGE','EXPIRY') AND from_facility_id IS NOT NULL AND to_facility_id IS NULL)
      ),
      CONSTRAINT fk_mv_batch FOREIGN KEY (batch_id) REFERENCES medicine_batch(batch_id),
      CONSTRAINT fk_mv_from  FOREIGN KEY (from_facility_id) REFERENCES facility(facility_id),
      CONSTRAINT fk_mv_to    FOREIGN KEY (to_facility_id) REFERENCES facility(facility_id),
      CONSTRAINT fk_mv_user  FOREIGN KEY (recorded_by) REFERENCES app_user(user_id),
      INDEX idx_mv_batch_date (batch_id, movement_date),
      INDEX idx_mv_to   (to_facility_id),
      INDEX idx_mv_from (from_facility_id)
    ) ENGINE=InnoDB
    """,
    """
    CREATE TABLE recall (
      recall_id     INT AUTO_INCREMENT PRIMARY KEY,
      recall_code   VARCHAR(30) NOT NULL UNIQUE,
      issued_date   DATE NOT NULL,
      reason        VARCHAR(255) NOT NULL,
      recall_class  ENUM('I','II','III') NOT NULL,
      recall_status ENUM('ACTIVE','CLOSED') NOT NULL DEFAULT 'ACTIVE'
    ) ENGINE=InnoDB
    """,
    """
    CREATE TABLE recall_affected_batch (
      recall_id INT NOT NULL,
      batch_id  INT NOT NULL,
      PRIMARY KEY (recall_id, batch_id),
      CONSTRAINT fk_rab_recall FOREIGN KEY (recall_id) REFERENCES recall(recall_id),
      CONSTRAINT fk_rab_batch  FOREIGN KEY (batch_id) REFERENCES medicine_batch(batch_id)
    ) ENGINE=InnoDB
    """,
    # --- immutable ledger -------------------------------------------------- #
    """
    CREATE TRIGGER trg_mv_no_update BEFORE UPDATE ON stock_movement
    FOR EACH ROW
    BEGIN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Ledger is append-only: UPDATE not allowed';
    END
    """,
    """
    CREATE TRIGGER trg_mv_no_delete BEFORE DELETE ON stock_movement
    FOR EACH ROW
    BEGIN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Ledger is append-only: DELETE not allowed';
    END
    """,
    # --- movement procedure ------------------------------------------------ #
    """
    CREATE PROCEDURE sp_record_movement(
      IN p_batch INT, IN p_from INT, IN p_to INT, IN p_type VARCHAR(20),
      IN p_qty INT, IN p_date DATE, IN p_ref VARCHAR(40), IN p_user INT)
    BEGIN
      DECLARE v_avail INT DEFAULT 0;
      DECLARE v_expiry DATE;
      DECLARE EXIT HANDLER FOR SQLEXCEPTION BEGIN ROLLBACK; RESIGNAL; END;

      START TRANSACTION;
      SELECT expiry_date INTO v_expiry
        FROM medicine_batch WHERE batch_id = p_batch FOR UPDATE;

      IF v_expiry IS NULL THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Unknown batch';
      END IF;
      IF p_date > CURDATE() THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Future movement date not allowed';
      END IF;
      IF p_type IN ('INITIAL_RECEIPT','TRANSFER') AND v_expiry < p_date THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Batch is expired';
      END IF;
      IF p_type = 'TRANSFER' AND EXISTS (
           SELECT 1 FROM recall_affected_batch rab
           JOIN recall r ON r.recall_id = rab.recall_id
           WHERE rab.batch_id = p_batch AND r.recall_status = 'ACTIVE') THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Batch under active recall: transfer blocked';
      END IF;

      IF p_from IS NOT NULL THEN
        SELECT COALESCE(SUM(CASE WHEN to_facility_id = p_from THEN quantity
                                 WHEN from_facility_id = p_from THEN -quantity ELSE 0 END), 0)
          INTO v_avail
          FROM stock_movement
         WHERE batch_id = p_batch AND (to_facility_id = p_from OR from_facility_id = p_from);
        IF v_avail < p_qty THEN
          SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Insufficient stock at source facility';
        END IF;
      END IF;

      INSERT INTO stock_movement
        (batch_id, from_facility_id, to_facility_id, movement_type, quantity,
         movement_date, reference_no, recorded_by)
      VALUES (p_batch, p_from, p_to, p_type, p_qty, p_date, p_ref, p_user);
      COMMIT;
    END
    """,
    # --- views ------------------------------------------------------------- #
    """
    CREATE VIEW v_current_stock AS
    SELECT s.facility_id, f.facility_name, f.district,
           s.batch_id, p.brand_name, b.batch_no, b.expiry_date, s.qty
    FROM (
      SELECT facility_id, batch_id, SUM(delta) AS qty
      FROM (
        SELECT to_facility_id   AS facility_id, batch_id,  quantity AS delta
          FROM stock_movement WHERE to_facility_id   IS NOT NULL
        UNION ALL
        SELECT from_facility_id AS facility_id, batch_id, -quantity AS delta
          FROM stock_movement WHERE from_facility_id IS NOT NULL
      ) m
      GROUP BY facility_id, batch_id
      HAVING SUM(delta) > 0
    ) s
    JOIN facility f         ON f.facility_id = s.facility_id
    JOIN medicine_batch b   ON b.batch_id    = s.batch_id
    JOIN medicine_product p ON p.product_id  = b.product_id
    """,
    """
    CREATE VIEW v_batch_timeline AS
    SELECT sm.batch_id, sm.movement_id, b.batch_no, p.brand_name, sm.movement_type,
           ff.facility_name AS from_facility, tf.facility_name AS to_facility,
           sm.quantity, sm.movement_date, sm.reference_no
    FROM stock_movement sm
    JOIN medicine_batch b   ON b.batch_id   = sm.batch_id
    JOIN medicine_product p ON p.product_id = b.product_id
    LEFT JOIN facility ff   ON ff.facility_id = sm.from_facility_id
    LEFT JOIN facility tf   ON tf.facility_id = sm.to_facility_id
    """,
    """
    CREATE VIEW v_recall_exposure AS
    SELECT r.recall_id, r.recall_code, r.recall_class, r.recall_status,
           cs.facility_id, cs.batch_id, cs.brand_name, cs.batch_no,
           cs.facility_name, cs.district, cs.qty
    FROM recall r
    JOIN recall_affected_batch rab ON rab.recall_id = r.recall_id
    JOIN v_current_stock cs        ON cs.batch_id   = rab.batch_id
    """,
    """
    CREATE VIEW v_expiry_watch AS
    SELECT brand_name, batch_no, facility_name, district, qty, expiry_date,
           DATEDIFF(expiry_date, CURDATE()) AS days_left
    FROM v_current_stock
    WHERE expiry_date <= DATE_ADD(CURDATE(), INTERVAL 90 DAY)
    """,
    """
    CREATE VIEW v_batches AS
    SELECT b.batch_id, b.product_id, p.brand_name, p.generic_name,
           b.batch_no, b.mfg_date, b.expiry_date
    FROM medicine_batch b
    JOIN medicine_product p ON p.product_id = b.product_id
    """,
]
