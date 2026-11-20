/**
 * MT CNC-Group API routes backed entirely by in-memory JavaScript data.
 * Data changes reset when the Node process restarts.
 */
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Static Admin account password: S1L1C0N. Keep only the bcrypt hash in source.
const ADMIN_PASSWORD_HASH = '$2b$12$Y47APYdBQpfoNWgrqcmQoe6qTggkQIqYGZ0AEtzcV8GJVojEGwJjm';
const DEFAULT_EMPLOYEE_HASH = '$2b$12$sR28Ox9361Gf9qoaj6TzM.XPvOPVeB6eiBLcRoSoa.HyML1f3IHV.';
const EMPLOYEE_PASSWORD_HASH = process.env.EMPLOYEE_PASSWORD_HASH || DEFAULT_EMPLOYEE_HASH;
if (process.env.NODE_ENV === 'production' && !process.env.EMPLOYEE_PASSWORD_HASH) {
  throw new Error('Production requires an EMPLOYEE_PASSWORD_HASH override.');
}
for (const hash of [ADMIN_PASSWORD_HASH, EMPLOYEE_PASSWORD_HASH]) {
  if (!/^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$/.test(hash)) throw new Error('Static account password settings must be bcrypt hashes.');
}
const STATIC_ACCOUNTS = [
  { id: 'static-admin', emp_id: 'Admin', username: 'Admin', full_name: 'Admin', role: 'admin', status: 'active', password_hash: ADMIN_PASSWORD_HASH },
  { id: 'static-employee', emp_id: '00000101', username: '00000101', full_name: 'Employee', role: 'employee', status: 'active', password_hash: EMPLOYEE_PASSWORD_HASH }
];
const staticAccountById = new Map(STATIC_ACCOUNTS.map((account) => [account.id, account]));
// Department credentials are independent of the employee/Admin session. Only
// bcrypt hashes live in source; mutable hashes and audit events live under runtime/.
const DEPARTMENT_AUTH_DEFINITIONS = Object.freeze({
  hr: Object.freeze({ department: 'HR', userId: 'HR_CIRCULARS', passwordHash: '$2b$12$qmcRXUfxSDMuCFHvF3VuwutrafKcS1aVune96xXXu2915Ax429knW' }),
  marketing: Object.freeze({ department: 'Marketing', userId: 'MARKETING_CIRCULARS', passwordHash: '$2b$12$/dE7pprkGf9B1T4LjU3WTeaSRODdBuWhuF9rb39ANaZrAi9A7e3PC' }),
  quality: Object.freeze({ department: 'Quality', userId: 'QUALITY_CIRCULARS', passwordHash: '$2b$12$DHOr7pyk0/KJr.JnUAIVOOTwLkCVRhwB0NlqumhAu3XuQ2FXSrrDG' }),
  canteen: Object.freeze({ department: 'Canteen', userId: 'CANTEEN_CIRCULARS', passwordHash: '$2b$12$KjrejuFUAUN.ms4saWaizO0AgvP7jE/EKSbf8Q2rYvE/bcYZZ.wiu' })
});
const PHONE_DIRECTORY_SOURCE = [
  {
    "department": "Accounts",
    "names": "Mr. Murugan / Mr. Vinoth Kumar",
    "phone_ext": "2001"
  },
  {
    "department": "Accounts",
    "names": "Surendran R / Vignesh G B",
    "phone_ext": "2002"
  },
  {
    "department": "Marketing",
    "names": "Mr. Muthu / Mrs. Rohini",
    "phone_ext": "2003"
  },
  {
    "department": "Design",
    "names": "Vinoth Kumar / Ramesh",
    "phone_ext": "2004"
  },
  {
    "department": "Sourcing",
    "names": "Mr. Ramamoorthy",
    "phone_ext": "2005"
  },
  {
    "department": "Purchase",
    "names": "Thyagarajulu N / Santhosh Rao S",
    "phone_ext": "2006"
  },
  {
    "department": "HRD",
    "names": "Mrs. Vijayarani",
    "phone_ext": "2007"
  },
  {
    "department": "HR & Admin",
    "names": "Mr. Prasanth Rajendran",
    "phone_ext": "2008"
  },
  {
    "department": "QAD Head",
    "names": "Mr. Mathaiyan Ayyandurai",
    "phone_ext": "2009"
  },
  {
    "department": "Finance Head",
    "names": "Mr. Ganesa Subramanian",
    "phone_ext": "2010"
  },
  {
    "department": "Marketing Head",
    "names": "Mr. Naveen Tilak HG",
    "phone_ext": "2012"
  },
  {
    "department": "HR Head",
    "names": "Dhandabani S",
    "phone_ext": "2013"
  },
  {
    "department": "Profit Agro Head",
    "names": "Mr. Prabu",
    "phone_ext": "2014"
  },
  {
    "department": "HR & Admin",
    "names": "Deepthi Muralibabu M",
    "phone_ext": "2018"
  },
  {
    "department": "Admin & SCM Head",
    "names": "Mr. Velappan R",
    "phone_ext": "2019"
  },
  {
    "department": "Chief Executive Officer",
    "names": "Mr. Narasimman L",
    "phone_ext": "2020"
  },
  {
    "department": "Executive Director",
    "names": "Mr. Ravi P",
    "phone_ext": "2021"
  },
  {
    "department": "IT Head",
    "names": "Mr. Selvaraj",
    "phone_ext": "2022"
  },
  {
    "department": "Joint Director",
    "names": "Mr. Vignesh Muralibabu",
    "phone_ext": "2023"
  },
  {
    "department": "Joint Director",
    "names": "Mr. Josepaul Johnson",
    "phone_ext": "2024"
  },
  {
    "department": "Director",
    "names": "Mr. Muralibabu",
    "phone_ext": "2025"
  },
  {
    "department": "Director",
    "names": "Mr. Johnson Paul",
    "phone_ext": "2026"
  },
  {
    "department": "Plant Head",
    "names": "Mr. Dhugaram",
    "phone_ext": "2028"
  },
  {
    "department": "Store",
    "names": "Mr. Kannadasan",
    "phone_ext": "2029"
  },
  {
    "department": "Maintenance / Quality",
    "names": "Mr. Madesh / Ashok",
    "phone_ext": "2030"
  },
  {
    "department": "Security Gate",
    "names": "Mr. Deepak",
    "phone_ext": "2032"
  },
  {
    "department": "CMM",
    "names": "Mr. Balakannan",
    "phone_ext": "2033"
  },
  {
    "department": "Canteen",
    "names": "Mrs. Vasanthi / Rathanamma",
    "phone_ext": "2034"
  },
  {
    "department": "Engineering",
    "names": "Mr. Manukumar T M / Mr. Chiranjeevi",
    "phone_ext": "2001"
  },
  {
    "department": "Marketing",
    "names": "Mr. Sadeshkumar",
    "phone_ext": "2002"
  },
  {
    "department": "Marketing",
    "names": "Mr. Purushotham A Athni / Mr. Vignesh D N",
    "phone_ext": "2003"
  },
  {
    "department": "Design & Development",
    "names": "Mr. Promod",
    "phone_ext": "2004"
  },
  {
    "department": "QMS",
    "names": "Mrs. Thenmozhi S",
    "phone_ext": "2006"
  }
];
const DEPARTMENT_EMAIL_SOURCE = [
  {
    "department": "ACCOUNTS",
    "email": "accounts-unit2@microtechcnc.in",
    "name": "Accounts-Unit2"
  },
  {
    "department": "ACCOUNTS",
    "email": "accounts-unit1@microtechcnc.in",
    "name": "Accounts Unit1"
  },
  {
    "department": "PRODUCTION",
    "email": "production-unit2@microtechcnc.in",
    "name": "Anandababu K"
  },
  {
    "department": "QUALITY",
    "email": "quality-unit2@microtechcnc.in",
    "name": "Arun"
  },
  {
    "department": "QUALITY",
    "email": "babu.t@microtechcnc.in",
    "name": "Babu T"
  },
  {
    "department": "ACCOUNTS",
    "email": "cfo@microtechcnc.in",
    "name": "Cfo"
  },
  {
    "department": "PRODUCTION",
    "email": "cncprogram@microtechcnc.in",
    "name": "Cncprogram"
  },
  {
    "department": "MARKETING",
    "email": "vignesh.dn@microtechcnc.in",
    "name": "D N Vignesh"
  },
  {
    "department": "MANAGEMENT",
    "email": "deepthimuralibabu@microtechcnc.in",
    "name": "Deepthi Muralibabu"
  },
  {
    "department": "STORES",
    "email": "stores-unit4@microtechcnc.in",
    "name": "Dhileeban M"
  },
  {
    "department": "PLANT HEAD",
    "email": "dhugaram@microtechcnc.in",
    "name": "Dhugaram S"
  },
  {
    "department": "HR",
    "email": "recruitment@microtechcnc.in",
    "name": "Elango Rajalingam"
  },
  {
    "department": "PRODUCTION",
    "email": "production-unit3@microtechcnc.in",
    "name": "Esaki Raja P"
  },
  {
    "department": "ACCOUNTS",
    "email": "finance-corp@microtechcnc.in",
    "name": "Ganesa Subramanian G V"
  },
  {
    "department": "GATE",
    "email": "gate@microtechcnc.in",
    "name": "Gate"
  },
  {
    "department": "HR",
    "email": "hrd-unit1@microtechcnc.in",
    "name": "Hrd-Unit1"
  },
  {
    "department": "HR",
    "email": "hrd-unit3@microtechcnc.in",
    "name": "Hrd-Unit3"
  },
  {
    "department": "TRAINEE",
    "email": "interns@microtechcnc.in",
    "name": "Interns"
  },
  {
    "department": "HR",
    "email": "microtechcnc-unit3@microtechcnc.in",
    "name": "Jayabalakrishan"
  },
  {
    "department": "MANAGEMENT",
    "email": "johnsonpaul@microtechcnc.in",
    "name": "Mr. Johnson Paul"
  },
  {
    "department": "NPD",
    "email": "toolroom-unit1@microtechcnc.in",
    "name": "Kalaiarasan G"
  },
  {
    "department": "QUALITY",
    "email": "quality-fab@microtechcnc.in",
    "name": "Kamalakannan S"
  },
  {
    "department": "PRODUCTION",
    "email": "presshop-unit3@microtechcnc.in",
    "name": "Kandeepan K"
  },
  {
    "department": "QUALITY",
    "email": "kkannan@microtechcnc.in",
    "name": "Kannan K"
  },
  {
    "department": "PRODUCTION",
    "email": "skmoorthy@microtechcnc.in",
    "name": "Krishnamoorthy S"
  },
  {
    "department": "PLANT HEAD",
    "email": "krishnan.p@microtechcnc.in",
    "name": "Krishnan P"
  },
  {
    "department": "QUALITY",
    "email": "kumar@microtechcnc.in",
    "name": "Kumar N"
  },
  {
    "department": "STORES",
    "email": "stores-unit2@microtechcnc.in",
    "name": "Lakshmi Narayanan M"
  },
  {
    "department": "PRODUCTION PLANNING",
    "email": "ppmc-unit1@microtechcnc.in",
    "name": "Logathiban K"
  },
  {
    "department": "MAINTENANCE",
    "email": "maintenance-unit1@microtechcnc.in",
    "name": "Madesh K M"
  },
  {
    "department": "MARKETING",
    "email": "costing@microtechcnc.in",
    "name": "Magesh Kumar"
  },
  {
    "department": "MAINTENANCE",
    "email": "maintenance-unit4@microtechcnc.in",
    "name": "Maintenance-Unit4"
  },
  {
    "department": "PRODUCTION PLANNING",
    "email": "ppmc-unit3@microtechcnc.in",
    "name": "Manikandan E"
  },
  {
    "department": "PROCESS ENGINEERING",
    "email": "manukumar.tm@microtechcnc.in",
    "name": "Manukumar.Tm"
  },
  {
    "department": "MARKETING",
    "email": "marketing@microtechcnc.in",
    "name": "Marketing"
  },
  {
    "department": "MARKETING",
    "email": "marketing-unit3@microtechcnc.in",
    "name": "Marketing Unit3"
  },
  {
    "department": "MICROTECHCNC",
    "email": "microtechcnc@microtechcnc.in",
    "name": "Microtechcnc"
  },
  {
    "department": "MICROTECHCNC",
    "email": "microtechcnc-unit4@microtechcnc.in",
    "name": "Microtechcnc-Unit4"
  },
  {
    "department": "MANAGEMENT",
    "email": "muralibabu@microtechcnc.in",
    "name": "Muralibabu G"
  },
  {
    "department": "MARKETING",
    "email": "rfq@microtechcnc.in",
    "name": "Muthuraman"
  },
  {
    "department": "CEO",
    "email": "narasimman.l@microtechcnc.in",
    "name": "Narasimman L"
  },
  {
    "department": "MARKETING",
    "email": "naveen.tilak@microtechcnc.in",
    "name": "Naveen Tilak"
  },
  {
    "department": "NPD",
    "email": "npd-unit1@microtechcnc.in",
    "name": "Npd Unit1"
  },
  {
    "department": "NPD",
    "email": "npd-unit3@microtechcnc.in",
    "name": "Npd Unit3"
  },
  {
    "department": "NPD",
    "email": "npdquality-unit3@microtechcnc.in",
    "name": "Npdquality-Unit3"
  },
  {
    "department": "PRODUCTION",
    "email": "palani@microtechcnc.in",
    "name": "Pazhani T"
  },
  {
    "department": "PROCESS ENGINEERING",
    "email": "ped@microtechcnc.in",
    "name": "Ped"
  },
  {
    "department": "STORES",
    "email": "stores-unit3@microtechcnc.in",
    "name": "Prakash E"
  },
  {
    "department": "HR",
    "email": "hrd@microtechcnc.in",
    "name": "Prasanth R"
  },
  {
    "department": "QUALITY",
    "email": "product-qa@microtechcnc.in",
    "name": "Product-Qa"
  },
  {
    "department": "PRODUCTION",
    "email": "product-unit3@microtechcnc.in",
    "name": "Product Unit3"
  },
  {
    "department": "PRODUCTION",
    "email": "production-unit1@microtechcnc.in",
    "name": "Production-Unit1"
  },
  {
    "department": "PURCHASE",
    "email": "purchase-unit3@microtechcnc.in",
    "name": "Purchase-Unit3"
  },
  {
    "department": "MARKETING",
    "email": "purushotham.Athni@microtechcnc.in",
    "name": "Purushotham Athni"
  },
  {
    "department": "QUALITY",
    "email": "qms-corp@microtechcnc.in",
    "name": "Qms Corp"
  },
  {
    "department": "QUALITY",
    "email": "quality-unit1@microtechcnc.in",
    "name": "Quality-Unit1"
  },
  {
    "department": "QUALITY",
    "email": "quality-unit4@microtechcnc.in",
    "name": "Quality-Unit4"
  },
  {
    "department": "MAINTENANCE",
    "email": "maintenance-unit3@microtechcnc.in",
    "name": "Raji B"
  },
  {
    "department": "NPD",
    "email": "raju.l@microtechcnc.in",
    "name": "Raju L"
  },
  {
    "department": "PURCHASE",
    "email": "sourcing@microtechcnc.in",
    "name": "Ramamoorthy R"
  },
  {
    "department": "NPD",
    "email": "ramesh.c@microtechcnc.in",
    "name": "Ramesh C"
  },
  {
    "department": "EXECUTIVE DIRECTOR",
    "email": "ravi@microtechcnc.in",
    "name": "Ravi P"
  },
  {
    "department": "ACCOUNTS",
    "email": "acs@microtechcnc.in",
    "name": "Rohini Ramanathan"
  },
  {
    "department": "PRODUCTION PLANNING",
    "email": "despatch-unit3@microtechcnc.in",
    "name": "Sakthivel S"
  },
  {
    "department": "PURCHASE",
    "email": "purchase-unit4@microtechcnc.in",
    "name": "Santhosh Rao S"
  },
  {
    "department": "MAINTENANCE",
    "email": "maintenance-unit2@microtechcnc.in",
    "name": "Saravanan R"
  },
  {
    "department": "NPD",
    "email": "sathishkumar.g@microtechcnc.in",
    "name": "Sathishkumar G"
  },
  {
    "department": "IT",
    "email": "itadmin@microtechcnc.in",
    "name": "Mr. Selvaraj"
  },
  {
    "department": "STORES",
    "email": "stores-unit1@microtechcnc.in",
    "name": "Stores-Unit1"
  },
  {
    "department": "QUALITY",
    "email": "teekaraman@microtechcnc.in",
    "name": "Teekaraman"
  },
  {
    "department": "MANAGEMENT",
    "email": "teenamariya@microtechcnc.in",
    "name": "Teena Mariya"
  },
  {
    "department": "QUALITY",
    "email": "quality-unit3@microtechcnc.in",
    "name": "Thangaraj"
  },
  {
    "department": "PURCHASE",
    "email": "thyagarajulu.n@microtechcnc.in",
    "name": "Thyagarajulu N"
  },
  {
    "department": "PURCHASE",
    "email": "purchase-unit1@microtechcnc.in",
    "name": "Uma Devi S"
  },
  {
    "department": "ACCOUNTS",
    "email": "accounts-unit3@microtechcnc.in",
    "name": "Vignesh G B"
  },
  {
    "department": "MANAGEMENT",
    "email": "vignesh.m@microtechcnc.in",
    "name": "Vignesh Muralibabu"
  },
  {
    "department": "PLANT HEAD",
    "email": "vinoth@microtechcnc.in",
    "name": "Vinoth V"
  },
  {
    "department": "PRODUCTION",
    "email": "machineshop-unit3@microtechcnc.in",
    "name": "Vinoth V"
  },
  {
    "department": "PRODUCTION",
    "email": "weldshop-unit3@microtechcnc.in",
    "name": "Weldshop-Unit3"
  },
  {
    "department": "MANAGEMENT",
    "email": "josepaul@microtechcnc.in",
    "name": "Josepaul"
  }
];
const normalizeDirectoryName = (value) => String(value || '').toLowerCase().replace(/\b(mr|mrs|ms|miss|dr)\b\.?/g, '').replace(/[^a-z0-9]/g, '');
const STATIC_EMPLOYEES = (() => {
  const contacts = [];
  const byName = new Map();
  const addContact = ({ name, department, phone_ext = '', email = '' }) => {
    const cleanName = String(name || '').replace(/\s+/g, ' ').trim();
    if (!cleanName || /\bcommon\b/i.test(cleanName) || /^mr\.?$/i.test(cleanName)) return;
    const key = normalizeDirectoryName(cleanName);
    const existing = byName.get(key);
    if (existing) {
      if (!existing.department && department) existing.department = department;
      if (phone_ext && !existing.phone_ext) existing.phone_ext = phone_ext;
      if (email && !existing.email.split(/[,;]\s*/).includes(email)) existing.email = [existing.email, email].filter(Boolean).join('; ');
      return;
    }
    const contact = { id: contacts.length + 1, emp_id: '', name: cleanName, designation: '', department: department || '', phone_ext, shift: '', email };
    contacts.push(contact);
    byName.set(key, contact);
  };
  for (const row of PHONE_DIRECTORY_SOURCE) {
    if (/common/i.test(row.names) || row.department === 'Department') continue;
    for (const name of row.names.split(/\s*\/\s*/)) addContact({ name, department: row.department, phone_ext: row.phone_ext });
  }
  for (const row of DEPARTMENT_EMAIL_SOURCE) addContact(row);
  return contacts;
})();
// Source: inter-comn (1).xlsx, Corp-Intercom worksheet. The two original
// extension lists are kept together; their S.No values are preserved as supplied.
const INTERCOM_DETAILS_SOURCE = [
  [1, 'Accounts', 'Mr. Murugan / Mr. Vinoth Kumar', 2001],
  [2, 'Accounts', 'Surendran R / Vignesh G B', 2002],
  [3, 'Marketing', 'Mr. Muthu / Mrs. Rohini', 2003],
  [4, 'Design ', 'Vinoth Kumar / Ramesh', 2004],
  [5, 'Sourcing', 'Mr. Ramamoorthy', 2005],
  [6, 'Purchase', 'Thyagarajulu N / Santhosh Rao S', 2006],
  [7, 'HRD', 'Mrs. Vijayarani', 2007],
  [8, 'HR & Admin', 'Mr. Prasanth Rajendran ', 2008],
  [9, 'QAD Head', 'Mr. Mathaiyan Ayyandurai', 2009],
  [10, 'Finance Head', 'Mr. Ganesa Subramanian', 2010],
  [11, 'CFO Head', 'Mr. ', 2011],
  [12, 'Marketing Head', 'Mr. Naveen Tilak HG', 2012],
  [13, 'HR Head', 'Dhandabani S', 2013],
  [14, 'Profit Agro Head', 'Mr. Prabu', 2014],
  [15, 'Board Room', 'Common', 2015],
  [16, 'Vendor Discussion Room', 'Common', 2016],
  [17, 'Reception', 'Common', 2017],
  [18, 'HR & Admin', 'Deepthi Muralibabu M', 2018],
  [19, 'Admin & SCM Head', null, 2019],
  [20, 'Chief Executive Officer', 'Mr. Narasimman L', 2020],
  [21, 'Executive Director', 'Mr. Ravi P', 2021],
  [22, 'IT Head', 'Mr. Selvaraj', 2022],
  [23, 'Joint Director', 'Mr. Vignesh Muralibabu', 2023],
  [24, 'Joint Director', 'Mr. Josepaul Johnson', 2024],
  [25, 'Director', 'Mr. Muralibabu', 2025],
  [26, 'Director', 'Mr. Johnson Paul', 2026],
  [27, 'Conference Room', 'Common', 2027],
  [28, 'Plant Head', 'Mr. Dhugaram', 2028],
  [29, 'Store', 'Mr. Kannadasan', 2029],
  [30, 'Maintenance / Quality', 'Mr. Madesh / Ashok', 2030],
  [31, 'Production Office', 'Production / Store /PPC Common', 2031],
  [32, 'Security Gate', 'Mr. Deepak', 2032],
  [33, 'CMM', 'Mr. Balakannan', 2033],
  [34, 'Canteen', 'Mrs. Vasanthi / Rathanamma', 2034],
  [35, 'Engineering', 'Mr. Manukumar T M / Mr. Chiranjeevi', 2003],
  [36, 'Marketing', 'Mr. Sadeshkumar', 2001],
  [37, 'Marketing', 'Mr. Purushotham A Athni / Mr. Vignesh D N', 2003],
  [38, 'Design & Development', 'Mr. Promod', 2004],
  [39, 'QMS', 'Mrs. Thenmozhi S', 2002]
];
const INTERCOM_DETAILS_COLUMNS = ['S.No', 'Department', 'Name', 'Tel.No'];
const MEMORY = {
  intercomDetails: INTERCOM_DETAILS_SOURCE.map((row, index) => ({
    id: index + 1, 'S.No': row[0], Department: row[1], Name: row[2], 'Tel.No': row[3]
  })),
  board: {
    last_incident_date: '2025-11-10',
    incident_free_target: 365,
    on_time_delivery: '98.5%',
    delivery_note: 'November Target Achieved',
    machines_down: '0 of 24',
    machines_note: 'All 24 machines operating at peak capacity'
  },
  announcements: [
    { id: 1, category: 'Safety', headline: 'Chip conveyor guards must stay closed during cycle', body: 'Operators must not open the chip conveyor guard while a program is running. Supervisors will check guards at each shift start.', is_pinned: 1, posted_date: '2026-11-09', created_by: 'static-admin' },
    { id: 2, category: 'Production', headline: 'Night shift moves to a 10 PM start from 1 December', body: 'Individual rosters will be shared by department heads.', is_pinned: 0, posted_date: '2026-11-08', created_by: 'static-admin' },
    { id: 3, category: 'Maintenance', headline: 'Scheduled preventive maintenance for VMC lines this Saturday', body: 'Lines 2 and 4 will be offline from 14:00 to 18:00 for hydraulic fluid flush and filter replacement.', is_pinned: 0, posted_date: '2026-11-07', created_by: 'static-admin' },
    { id: 4, category: 'Quality', headline: 'Zero-defect initiative audit scheduled for next week', body: 'All quality inspection checklists must be updated at workstations before 15 November.', is_pinned: 0, posted_date: '2026-11-06', created_by: 'static-admin' }
  ],
  events: [
    { id: 1, event_date: '2026-11-14', title: 'Quarterly Safety Committee Review', place_and_time: 'Main Conference Hall, 10:00 AM', created_by: 'static-admin' },
    { id: 2, event_date: '2026-11-18', title: '5S Shop Floor Excellence Walk', place_and_time: 'Shop Floor Bays 1-4, 02:30 PM', created_by: 'static-admin' },
    { id: 3, event_date: '2026-11-25', title: 'Blood Donation Camp', place_and_time: 'Employee Wellness Center, 09:00 AM - 04:00 PM', created_by: 'static-admin' },
    { id: 4, event_date: '2026-12-05', title: 'Annual Plant Townhall & Awards', place_and_time: 'Auditorium & Live Stream, 03:00 PM', created_by: 'static-admin' }
  ],
  hrContacts: [
    { id: 1, name: 'Flango Rajalingam', department: 'HR', phone_ext: '', email: 'recruitment@microtechcnc.in' },
    { id: 2, name: 'Hrd-Unit1', department: 'HR', phone_ext: '', email: 'hrd-unit1@microtechcnc.in' },
    { id: 3, name: 'Hrd-Unit3', department: 'HR', phone_ext: '', email: 'hrd-unit3@microtechcnc.in' },
    { id: 4, name: 'Jayabalakrishan', department: 'HR', phone_ext: '', email: 'microtechcnc-unit3@microtechcnc.in' },
    { id: 5, name: 'Prasanth R', department: 'HR', phone_ext: '', email: 'hrd@microtechcnc.in' }
  ],
  tickets: [], suggestions: [], holidays: [
    { id: 1, holiday_date: '2026-11-09', name: 'Deepavali', day_name: 'Monday', status: 'Completed' },
    { id: 2, holiday_date: '2026-01-15', name: 'Pongal', day_name: 'Thursday', status: 'Completed' },
    { id: 3, holiday_date: '2026-01-16', name: 'Thiruvalluvar Day', day_name: 'Friday', status: 'Completed' },
    { id: 4, holiday_date: '2026-01-26', name: 'Republic Day', day_name: 'Monday', status: 'Completed' },
    { id: 5, holiday_date: '2026-04-14', name: 'Tamil New Year Day', day_name: 'Tuesday', status: 'Completed' },
    { id: 6, holiday_date: '2026-05-01', name: 'May Day', day_name: 'Friday', status: 'Completed' },
    { id: 7, holiday_date: '2026-08-15', name: 'Independence Day', day_name: 'Saturday', status: 'Completed' },
    { id: 8, holiday_date: '2026-09-14', name: 'Vinayakar Chaturthi', day_name: 'Monday', status: 'Completed' },
    { id: 9, holiday_date: '2026-10-02', name: 'Gandhi Jayanthi', day_name: 'Friday', status: 'Completed' }
  ], links: []
};
const ASSET_COLUMNS = [
  "User Id",
  "Name",
  "Endpoint Name",
  "IP Address",
  "Endpoint Status",
  "Roaming Service",
  "Domain Name",
  "Group Name",
  "User Name",
  "Policy",
  "Policy Status",
  "Virus DB Date (GMT+5:30)",
  "Last Connected",
  "Last Scanned",
  "MAC Address",
  "Serial Number",
  "Client Version",
  "Operating System",
  "DLP",
  "AV Status",
  "EDR Sensor Version"
];
const STATIC_ASSETS = [
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PRODUCTION3-D1",
    "IP Address": "10.24.3.4",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PRODUCTION3-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:14]",
    "Last Scanned": "02 Nov 2026 [12:00:22]",
    "MAC Address": "8C-EC-4B-60-0E-F6",
    "Serial Number": "1Y9GGP2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MPIPL01-L1",
    "IP Address": "192.168.1.41",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "MPIPL-L1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "11 Nov 2026 [14:12:45]",
    "Last Connected": "11 Nov 2026 [16:55:45]",
    "Last Scanned": "10 Oct 2026 [14:01:15]",
    "MAC Address": "E4-0D-36-12-54-CB",
    "Serial Number": "5CD337GV05",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "NPD3-D3",
    "IP Address": "10.24.3.97",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "NPD3-D3",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:29]",
    "Last Scanned": "07 Nov 2026 [12:21:35]",
    "MAC Address": "98-90-96-C9-DB-D5",
    "Serial Number": "G0WR542",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MAINT1-L1",
    "IP Address": "172.32.2.79",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->UnBlockUSB",
    "User Name": "MAINTM1-L1",
    "Policy": "UnBlockUSB",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [00:02:17]",
    "Last Connected": "13 Nov 2026 [08:56:37]",
    "Last Scanned": "17 Oct 2026 [13:10:48]",
    "MAC Address": "B0-C0-90-C6-6E-E4",
    "Serial Number": "GJ695C2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PEDCORP-NB1",
    "IP Address": "10.24.1.230",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "CORPMKT-L1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "12 Nov 2026 [18:29:05]",
    "Last Scanned": "31 Oct 2026 [12:53:28]",
    "MAC Address": "F8-FE-5E-D4-B8-EF",
    "Serial Number": "5CD411JN8K",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "RFQU1-L2",
    "IP Address": "10.24.1.64",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "RFQU1-L2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:36]",
    "Last Scanned": "24 Oct 2026 [13:56:14]",
    "MAC Address": "9C-C7-D3-65-B6-FC",
    "Serial Number": "5CG5343VS9",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "U4MFGHEAD-L2",
    "IP Address": "172.32.2.80",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll_WhatsApp",
    "User Name": "U4MFGHEAD-L2",
    "Policy": "BlockAll_WhatsApp",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "11 Nov 2026 [14:12:45]",
    "Last Connected": "12 Nov 2026 [19:56:10]",
    "Last Scanned": "24 Oct 2026 [11:29:05]",
    "MAC Address": "9C-C7-D3-52-D4-16",
    "Serial Number": "5CG5343VYP",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "U2MFGHEAD-L3",
    "IP Address": "10.24.2.120",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->UnBlockUSB",
    "User Name": "U2MFGHEAD-L3",
    "Policy": "UnBlockUSB",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:59]",
    "Last Scanned": "11 Nov 2026 [12:42:01]",
    "MAC Address": "9C-C7-D3-4F-E2-D6",
    "Serial Number": "5CG5343T7Z",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "DEVELOPMENT",
    "IP Address": "10.24.3.98",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "DEVELOPMENT",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:23]",
    "Last Scanned": "03 Oct 2026 [14:35:04]",
    "MAC Address": "40-ED-00-21-DE-BB",
    "Serial Number": "FRPTDV2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "HP11-HYPERV-RDP",
    "IP Address": "172.32.2.14",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->RDP Server",
    "User Name": "Administrator",
    "Policy": "RDP Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:04]",
    "Last Scanned": "-",
    "MAC Address": "00-15-5D-02-0B-08",
    "Serial Number": "8997-2588-8871-0251-7243-0556-65",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2016 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "STORES4-D2",
    "IP Address": "10.24.1.229",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "STORES4-D2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [11:08:15]",
    "Last Connected": "13 Nov 2026 [09:32:13]",
    "Last Scanned": "31 Oct 2026 [12:15:59]",
    "MAC Address": "9C-B1-50-56-C5-D9",
    "Serial Number": "HH41P24",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "QADM1-D2",
    "IP Address": "10.24.1.169",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->UnBlockUSB",
    "User Name": "QADM1-D2",
    "Policy": "UnBlockUSB",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "09 Oct 2026 [14:25:58]",
    "Last Connected": "09 Oct 2026 [16:34:05]",
    "Last Scanned": "07 Oct 2026 [15:59:57]",
    "MAC Address": "98-90-96-C9-D6-42",
    "Serial Number": "G1WR542",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTG-PDC",
    "IP Address": "10.24.1.25",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "MTG-MT-RDP1$",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:23]",
    "Last Scanned": "-",
    "MAC Address": "00-15-5D-BB-67-00",
    "Serial Number": "9673-8510-5309-4864-4933-0245-19",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2022 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "CFO1-L1",
    "IP Address": "10.24.1.131",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "CFO-L1",
    "Policy": "BlockAll",
    "Policy Status": "Published",
    "Virus DB Date (GMT+5:30)": "19 Oct 2026 [08:41:05]",
    "Last Connected": "19 Oct 2026 [12:08:49]",
    "Last Scanned": "10 Oct 2026 [12:18:01]",
    "MAC Address": "C8-58-C0-82-E7-90",
    "Serial Number": "69P8WZ2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "CNCPROGRAM1-D1",
    "IP Address": "10.24.1.75",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "CNCPROGRAM-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:01:59]",
    "Last Scanned": "31 Oct 2026 [12:10:02]",
    "MAC Address": "84-5C-31-FF-FA-2C",
    "Serial Number": "F3P6R24",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "DESPATCH3-D1",
    "IP Address": "10.24.3.51",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "DESPATCH3-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:52]",
    "Last Scanned": "31 Oct 2026 [12:53:08]",
    "MAC Address": "8C-EC-4B-60-4C-4F",
    "Serial Number": "1XGNGP2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTG-VM-IT",
    "IP Address": "10.24.1.28",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:04]",
    "Last Scanned": "-",
    "MAC Address": "00-15-5D-28-97-01",
    "Serial Number": "4748-3613-2226-5593-2788-6448-12",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2022 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTG-Hyperv-21",
    "IP Address": "10.24.1.22",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "Administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:34]",
    "Last Scanned": "-",
    "MAC Address": "14-23-F2-79-4D-0C",
    "Serial Number": "CNXD1B01M3",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2022 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "ADMIN3-D1",
    "IP Address": "10.24.3.76",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "ADMIN3-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [11:08:15]",
    "Last Connected": "12 Nov 2026 [17:35:36]",
    "Last Scanned": "17 Oct 2026 [12:40:51]",
    "MAC Address": "64-00-6A-14-BD-7A",
    "Serial Number": "3J6K882",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "HP11-VM-ADC",
    "IP Address": "172.32.2.25",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "Administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:07]",
    "Last Scanned": "-",
    "MAC Address": "00-15-5D-02-0B-0B",
    "Serial Number": "8580-5155-6985-7725-9393-2825-71",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2022 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "QUALITY3-D1",
    "IP Address": "10.24.3.57",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "QUALITY3-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:09]",
    "Last Scanned": "07 Nov 2026 [12:40:17]",
    "MAC Address": "54-48-10-FF-D9-C0",
    "Serial Number": "18QJXH2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "COSTING1-L1",
    "IP Address": "10.24.1.120",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "U1COSTING-L1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:56]",
    "Last Scanned": "31 Oct 2026 [12:40:47]",
    "MAC Address": "E4-A4-71-2E-B1-2A",
    "Serial Number": "CCMXKC2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "NPD3-D5",
    "IP Address": "10.24.3.70",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "NPD3-D5",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:00]",
    "Last Scanned": "31 Oct 2026 [12:19:50]",
    "MAC Address": "E4-54-E8-CB-16-A5",
    "Serial Number": "11MXJ23",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTG-Hyperv-20",
    "IP Address": "10.24.1.23",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "Administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:57]",
    "Last Scanned": "-",
    "MAC Address": "14-23-F2-74-2A-BF",
    "Serial Number": "CNXD1B018Y",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2022 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "QADU1-NB1",
    "IP Address": "10.24.1.232",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "FINANCE1-L1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:33]",
    "Last Scanned": "17 Oct 2026 [12:44:07]",
    "MAC Address": "F8-FE-5E-D2-6A-27",
    "Serial Number": "5CD411JN3H",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "LASERCUTTING3-D1",
    "IP Address": "10.24.3.100",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "LASERCUTTING3-D2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:15]",
    "Last Scanned": "31 Oct 2026 [12:33:13]",
    "MAC Address": "00-BE-43-B7-D4-9E",
    "Serial Number": "D7DNQR3",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTG-VM-EPS",
    "IP Address": "10.24.1.102",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:18]",
    "Last Scanned": "10 Oct 2026 [12:17:19]",
    "MAC Address": "00-15-5D-BB-67-0D",
    "Serial Number": "8465-5477-0382-0525-9968-4557-95",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2022 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "SCM-ADMIN-L1",
    "IP Address": "10.24.1.134",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "CORPQAD-L1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:32]",
    "Last Scanned": "31 Oct 2026 [12:33:45]",
    "MAC Address": "50-5A-65-B2-D2-C7",
    "Serial Number": "5CD2510PCZ",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "STORES3-D1",
    "IP Address": "10.24.3.27",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "STORES3-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [10:02:44]",
    "Last Scanned": "31 Oct 2026 [12:33:35]",
    "MAC Address": "8C-EC-4B-CB-9F-11",
    "Serial Number": "B7JV3W2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MKT3-L2",
    "IP Address": "10.24.3.136",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "MKT3-NB2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [11:08:15]",
    "Last Connected": "13 Nov 2026 [09:59:50]",
    "Last Scanned": "31 Oct 2026 [12:36:07]",
    "MAC Address": "08-F9-7E-58-5D-73",
    "Serial Number": "54KNVF4",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "SELVARAJ-IT",
    "IP Address": "10.24.1.99",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "adminse",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:29]",
    "Last Scanned": "14 Aug 2026 [00:29:23]",
    "MAC Address": "00-BE-43-8D-E1-93",
    "Serial Number": "23C7SN3",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "RFQ-L1",
    "IP Address": "10.24.1.122",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "RFQ1-L1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:13]",
    "Last Scanned": "31 Oct 2026 [12:26:19]",
    "MAC Address": "28-3A-4D-53-5A-9B",
    "Serial Number": "F9TMWS2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PURCHASE1_L1",
    "IP Address": "10.24.1.199",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PURCHASE1-L1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "11 Nov 2026 [14:12:45]",
    "Last Connected": "13 Nov 2026 [09:37:59]",
    "Last Scanned": "12 Sep 2026 [14:36:20]",
    "MAC Address": "0C-96-E6-40-C4-3F",
    "Serial Number": "2BC4XS2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "SISRVR",
    "IP Address": "172.32.2.96",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "Administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:30]",
    "Last Scanned": "-",
    "MAC Address": "00-0C-29-7F-E1-81",
    "Serial Number": "VMware-56 4d 5b 4e 74 c2 b5 cf-19 32 c6 29 f7 7f e1 81",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2016 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MPIPL4-D4",
    "IP Address": "192.168.1.10",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "WORKGROUP",
    "Group Name": "Micro-Tech Group->BlockAll_WhatsApp",
    "User Name": "MPIPL-D4",
    "Policy": "BlockAll_WhatsApp",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [11:08:15]",
    "Last Connected": "13 Nov 2026 [09:55:45]",
    "Last Scanned": "19 Sep 2026 [12:32:39]",
    "MAC Address": "98-90-96-C9-DA-7D",
    "Serial Number": "HWVR542",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "U3PHD01-L1",
    "IP Address": "10.24.3.127",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll GDrive",
    "User Name": "Admin",
    "Policy": "BlockAll GDrive",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:48]",
    "Last Scanned": "31 Oct 2026 [12:24:31]",
    "MAC Address": "F8-FE-5E-D4-AA-08",
    "Serial Number": "5CD411JN61",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PRODUCTION3-D2",
    "IP Address": "10.24.3.58",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PRODUCTION3-D2",
    "Policy": "BlockAll",
    "Policy Status": "Published",
    "Virus DB Date (GMT+5:30)": "15 Oct 2026 [08:28:39]",
    "Last Connected": "15 Oct 2026 [14:42:01]",
    "Last Scanned": "10 Oct 2026 [12:32:41]",
    "MAC Address": "34-17-EB-BA-C4-C2",
    "Serial Number": "CKCSH32",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "ASC1-L1",
    "IP Address": "192.168.1.106",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "ACS-L1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "11 Nov 2026 [14:12:45]",
    "Last Connected": "11 Nov 2026 [19:50:45]",
    "Last Scanned": "19 Sep 2026 [14:31:54]",
    "MAC Address": "C8-58-C0-82-BC-3E",
    "Serial Number": "2BP8WZ2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "HRDU1-L3",
    "IP Address": "10.24.1.177",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "NPD1-L3",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:06]",
    "Last Scanned": "03 Oct 2026 [14:28:50]",
    "MAC Address": "A8-E2-91-F0-BA-00",
    "Serial Number": "5CG514039F",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "U4PLNTMGR-NB1",
    "IP Address": "10.24.1.233",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll_WhatsApp",
    "User Name": "PLANTMGR4-NB1",
    "Policy": "BlockAll_WhatsApp",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [08:47:35]",
    "Last Connected": "12 Nov 2026 [13:04:05]",
    "Last Scanned": "-",
    "MAC Address": "F8-FE-5E-D4-8D-D4",
    "Serial Number": "5CD411JN4T",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "ACCOUNTS1-D5",
    "IP Address": "10.24.1.40",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "ACCOUNTS1-D5",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:18]",
    "Last Scanned": "31 Oct 2026 [12:25:39]",
    "MAC Address": "20-88-10-70-F0-0D",
    "Serial Number": "J9YDWY3",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PEDU1-NB2",
    "IP Address": "172.32.2.88",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PED-NB2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:11]",
    "Last Scanned": "31 Oct 2026 [14:33:09]",
    "MAC Address": "08-F9-7E-58-62-EB",
    "Serial Number": "79GNVF4",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "STORESU1-D2",
    "IP Address": "10.24.1.71",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "STORES1-D2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:15]",
    "Last Scanned": "31 Oct 2026 [12:15:09]",
    "MAC Address": "9C-67-D6-6B-6D-22",
    "Serial Number": "52P0P24",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTG-Hyperv-11",
    "IP Address": "172.32.2.11",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "Administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:52]",
    "Last Scanned": "-",
    "MAC Address": "58-20-B1-EA-DC-00",
    "Serial Number": "",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2016 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "U1NPD-L1",
    "IP Address": "10.24.1.136",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "U1NPD-L1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [10:02:03]",
    "Last Scanned": "31 Oct 2026 [12:44:19]",
    "MAC Address": "E4-A4-71-2E-B0-3F",
    "Serial Number": "GB5YKC2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "U4MFGHEAD-L1",
    "IP Address": "172.32.2.84",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll_WhatsApp",
    "User Name": "U4MFGHEAD-L1",
    "Policy": "BlockAll_WhatsApp",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "11 Nov 2026 [14:12:45]",
    "Last Connected": "13 Nov 2026 [10:02:11]",
    "Last Scanned": "02 Jul 2026 [12:58:23]",
    "MAC Address": "F8-FE-5E-D4-8D-3E",
    "Serial Number": "5CD411JN4V",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "BHCORP-NB1",
    "IP Address": "10.24.1.59",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->OpenAll",
    "User Name": "BHCORP-NB1",
    "Policy": "OpenAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "12 Nov 2026 [16:58:28]",
    "Last Scanned": "15 Oct 2026 [14:37:31]",
    "MAC Address": "AC-19-8E-D1-D1-BB",
    "Serial Number": "5CD3231DL5",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MARKETING3-D1",
    "IP Address": "10.24.3.121",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Default",
    "User Name": "WELDING3-D1",
    "Policy": "Default_EPP",
    "Policy Status": "Not Published",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "12 Nov 2026 [18:13:27]",
    "Last Scanned": "31 Oct 2026 [12:51:01]",
    "MAC Address": "D4-BE-D9-91-AD-81",
    "Serial Number": "GBMRWQ1",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MURALIBABU-NB1",
    "IP Address": "172.32.2.94",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->OpenAll",
    "User Name": "MURALIBABU-L1",
    "Policy": "OpenAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [09:57:03]",
    "Last Scanned": "14 Aug 2026 [11:33:36]",
    "MAC Address": "28-11-A8-43-F2-AB",
    "Serial Number": "5CD1462S4F",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PRODUCTION1-D1",
    "IP Address": "10.24.1.73",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PRODUCTION1-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:22]",
    "Last Scanned": "31 Oct 2026 [12:10:39]",
    "MAC Address": "9C-67-D6-6E-03-34",
    "Serial Number": "219ZN24",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "NPDu3-d1",
    "IP Address": "10.24.3.71",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "NPD3-D4",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:50]",
    "Last Scanned": "31 Oct 2026 [12:30:04]",
    "MAC Address": "64-00-6A-7B-9D-9A",
    "Serial Number": "1YQHH92",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "SCM3-D1",
    "IP Address": "10.24.3.123",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "SCM3-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [10:03:05]",
    "Last Scanned": "07 Nov 2026 [14:09:08]",
    "MAC Address": "8C-EC-4B-6F-6E-E7",
    "Serial Number": "HST1N62",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 8.1 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PRODUCTION2A-D1",
    "IP Address": "192.168.1.5",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "WORKGROUP",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "Production2-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [09:50:46]",
    "Last Scanned": "10 Oct 2026 [12:36:24]",
    "MAC Address": "50-9A-4C-38-D3-46",
    "Serial Number": "8DJDZL2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "HRDU1-D1",
    "IP Address": "10.24.1.147",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "HRDU1-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:00:46]",
    "Last Scanned": "31 Oct 2026 [12:15:38]",
    "MAC Address": "98-90-96-C9-D6-C4",
    "Serial Number": "F1WR542",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "VOLVO3-D1",
    "IP Address": "10.24.3.137",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "WORKGROUP",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "VOLVO-D1",
    "Policy": "BlockAll",
    "Policy Status": "Published",
    "Virus DB Date (GMT+5:30)": "23 Oct 2026 [08:33:35]",
    "Last Connected": "23 Oct 2026 [12:14:41]",
    "Last Scanned": "17 Oct 2026 [14:42:04]",
    "MAC Address": "48-4D-7E-9E-B7-1C",
    "Serial Number": "HSTJH92",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "STOREU1-D1",
    "IP Address": "10.24.1.70",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "STOREU1-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:19]",
    "Last Scanned": "31 Oct 2026 [12:12:17]",
    "MAC Address": "9C-67-D6-6B-7A-F6",
    "Serial Number": "F4P0P24",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "LASERCUTTING4",
    "IP Address": "10.24.1.216",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->UnBlockUSB",
    "User Name": "LASERCUT4-D1",
    "Policy": "UnBlockUSB",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "11 Nov 2026 [14:12:45]",
    "Last Connected": "13 Nov 2026 [10:03:46]",
    "Last Scanned": "04 Nov 2026 [13:06:07]",
    "MAC Address": "CC-96-E5-1D-98-AE",
    "Serial Number": "FV117X3",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "FARO4-L2",
    "IP Address": "10.24.1.231",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "WORKGROUP",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "POLYWORKS",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:35]",
    "Last Scanned": "31 Oct 2026 [12:49:05]",
    "MAC Address": "64-79-F0-CA-88-61",
    "Serial Number": "5CD119FZCM",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MKT3-L1",
    "IP Address": "172.32.2.89",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll GDrive",
    "User Name": "MKT3-NB1",
    "Policy": "BlockAll GDrive",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [09:37:33]",
    "Last Scanned": "31 Oct 2026 [14:58:23]",
    "MAC Address": "08-F9-7E-57-A6-13",
    "Serial Number": "3NMNVF4",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTCNC1-D1",
    "IP Address": "10.24.1.174",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "MTCNC-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:16]",
    "Last Scanned": "31 Oct 2026 [14:16:41]",
    "MAC Address": "54-BF-64-76-96-FF",
    "Serial Number": "D3YG9R2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "ACCOUNTS1-D2",
    "IP Address": "10.24.1.151",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "ACCOUNTS1-D2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:25]",
    "Last Scanned": "31 Oct 2026 [12:10:04]",
    "MAC Address": "FC-4C-EA-1A-A3-FF",
    "Serial Number": "JS9HBK4",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "HRD-L1",
    "IP Address": "10.24.1.68",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "HRDU1-L1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [10:02:23]",
    "Last Scanned": "31 Oct 2026 [17:03:48]",
    "MAC Address": "9C-C7-D3-4F-4C-8A",
    "Serial Number": "5CG5343WXG",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "HRDU1-L2",
    "IP Address": "10.24.1.188",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "HRDU1-L2",
    "Policy": "BlockAll",
    "Policy Status": "Published",
    "Virus DB Date (GMT+5:30)": "26 Oct 2026 [13:18:13]",
    "Last Connected": "26 Oct 2026 [17:20:50]",
    "Last Scanned": "01 Aug 2026 [13:11:24]",
    "MAC Address": "A8-E2-91-EE-E1-32",
    "Serial Number": "5CG5140399",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "QADU1-NB2",
    "IP Address": "10.24.1.227",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "QADU1-NB2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:06]",
    "Last Scanned": "17 Oct 2026 [12:30:07]",
    "MAC Address": "E4-A4-71-2E-B0-FD",
    "Serial Number": "J7MXKC2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "SOURCING-NB3",
    "IP Address": "192.168.1.100",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG2",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "Administrator",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [09:50:46]",
    "Last Scanned": "24 Oct 2026 [12:34:10]",
    "MAC Address": "34-02-86-B8-47-50",
    "Serial Number": "5CG525402W",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 8.1 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "HRD3-D1",
    "IP Address": "10.24.3.122",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "admin",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "05 Nov 2026 [10:49:44]",
    "Last Connected": "11 Nov 2026 [12:58:01]",
    "Last Scanned": "31 Oct 2026 [12:18:45]",
    "MAC Address": "E4-54-E8-CB-16-99",
    "Serial Number": "61MXJ23",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "GATE1-D1",
    "IP Address": "10.24.1.154",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "GATE1-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [11:08:15]",
    "Last Connected": "13 Nov 2026 [10:02:01]",
    "Last Scanned": "31 Oct 2026 [12:17:46]",
    "MAC Address": "C0-25-A5-AB-9D-DD",
    "Serial Number": "DC70BM3",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MAINTENANCE1-D1",
    "IP Address": "10.24.1.118",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "QUALITY1-D2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:52]",
    "Last Scanned": "31 Oct 2026 [15:12:25]",
    "MAC Address": "7C-05-07-0E-E0-D9",
    "Serial Number": "",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "QADHEAD-L2",
    "IP Address": "192.168.0.102",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "Q-HEAD-L2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "11 Nov 2026 [08:36:29]",
    "Last Connected": "12 Nov 2026 [11:00:46]",
    "Last Scanned": "31 Oct 2026 [12:26:34]",
    "MAC Address": "14-85-7F-19-4E-11",
    "Serial Number": "5CD124JMFT",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PURCHASE1-D1",
    "IP Address": "10.24.1.145",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PURCHASE1-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:02]",
    "Last Scanned": "17 Oct 2026 [12:37:31]",
    "MAC Address": "98-90-96-C9-DA-DB",
    "Serial Number": "J1WR542",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "ACCOUNTSU1-D2",
    "IP Address": "10.24.2.26",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "GATE2-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [11:08:15]",
    "Last Connected": "12 Nov 2026 [15:06:20]",
    "Last Scanned": "31 Oct 2026 [12:22:10]",
    "MAC Address": "48-4D-7E-A6-80-BA",
    "Serial Number": "18SFXH2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "ICQC-D1",
    "IP Address": "10.24.1.143",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "ICQAD1-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:00]",
    "Last Scanned": "31 Oct 2026 [12:34:38]",
    "MAC Address": "50-9A-4C-08-8F-F5",
    "Serial Number": "6RW7NK2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "QADM1-D4",
    "IP Address": "10.24.1.152",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "QADM1-D4",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [09:46:23]",
    "Last Scanned": "31 Oct 2026 [12:32:47]",
    "MAC Address": "98-90-96-C9-DA-F3",
    "Serial Number": "62WR542",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PPMCM1-D1",
    "IP Address": "10.24.1.148",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PPMCM1-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [10:04:27]",
    "Last Scanned": "31 Oct 2026 [12:39:21]",
    "MAC Address": "98-90-96-C9-D4-4F",
    "Serial Number": "33WR542",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PRODU4-D1",
    "IP Address": "10.24.1.214",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PROD4-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [10:03:00]",
    "Last Scanned": "24 Oct 2026 [14:27:07]",
    "MAC Address": "20-88-10-8F-64-46",
    "Serial Number": "76XBS14",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PPMC2-D1",
    "IP Address": "10.24.2.20",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PPMCU2-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:16]",
    "Last Scanned": "17 Oct 2026 [12:29:16]",
    "MAC Address": "8C-EC-4B-AA-4A-9A",
    "Serial Number": "DQ507T2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "ACCOUNTSU1-L2",
    "IP Address": "10.24.1.76",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "ACCOUNTS1-L2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:49]",
    "Last Scanned": "31 Oct 2026 [14:25:33]",
    "MAC Address": "08-F9-7E-57-AC-AF",
    "Serial Number": "5YLNVF4",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MPIPL-D2",
    "IP Address": "192.168.1.37",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MPIPL",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "MPIPL D2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "07 Nov 2026 [11:02:25]",
    "Last Connected": "12 Nov 2026 [09:55:46]",
    "Last Scanned": "07 Nov 2026 [12:14:09]",
    "MAC Address": "20-88-10-8D-5B-41",
    "Serial Number": "JSSBS14",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "CEOCORP-L1",
    "IP Address": "192.168.101.11",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->OpenAll",
    "User Name": "CORP-CEO",
    "Policy": "OpenAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [08:47:35]",
    "Last Connected": "13 Nov 2026 [07:40:46]",
    "Last Scanned": "19 Oct 2026 [11:31:11]",
    "MAC Address": "F8-FE-5E-D2-87-2D",
    "Serial Number": "5CD411JN55",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTG-VM-TIME",
    "IP Address": "10.24.1.27",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "Administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:01:59]",
    "Last Scanned": "-",
    "MAC Address": "00-15-5D-28-97-00",
    "Serial Number": "4449-3444-3445-6523-3458-0070-92",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2022 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "FARO",
    "IP Address": "10.24.1.222",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "admin",
    "Policy": "BlockAll",
    "Policy Status": "Published",
    "Virus DB Date (GMT+5:30)": "20 Oct 2026 [09:54:01]",
    "Last Connected": "20 Oct 2026 [13:23:24]",
    "Last Scanned": "17 Oct 2026 [13:18:47]",
    "MAC Address": "90-65-84-D3-24-C6",
    "Serial Number": "5CG3440K72",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTG-MT-RDP",
    "IP Address": "10.24.1.11",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->RDP Server",
    "User Name": "Administrator",
    "Policy": "RDP Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:04]",
    "Last Scanned": "-",
    "MAC Address": "00-15-5D-BB-67-0C",
    "Serial Number": "0699-7101-1115-0567-6877-8057-25",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2016 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "U1MFGHEAD-L1",
    "IP Address": "10.24.1.184",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll_WhatsApp",
    "User Name": "U1MFGHEAD-L1",
    "Policy": "BlockAll_WhatsApp",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [10:03:43]",
    "Last Scanned": "-",
    "MAC Address": "F8-FE-5E-D6-2E-23",
    "Serial Number": "5CD411JN3Q",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "DDP1-D2",
    "IP Address": "10.24.3.134",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "DDP3-D2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:01]",
    "Last Scanned": "07 Nov 2026 [12:45:35]",
    "MAC Address": "F4-8E-38-82-AB-A8",
    "Serial Number": "GTYZXC2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "U1QADHEAD-L3",
    "IP Address": "172.30.1.85",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "U1QADHEAD-L3",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [09:55:45]",
    "Last Scanned": "31 Oct 2026 [13:52:28]",
    "MAC Address": "F8-FE-5E-D6-2D-8D",
    "Serial Number": "5CD411JN48",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MAINTENANCE2-D1",
    "IP Address": "10.24.2.43",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "admin",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "04 Nov 2026 [14:19:58]",
    "Last Connected": "05 Nov 2026 [08:55:52]",
    "Last Scanned": "24 Oct 2026 [12:59:39]",
    "MAC Address": "00-E0-4C-CD-4F-A4",
    "Serial Number": "To be filled by O.E.M.",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MAINTM1-D1",
    "IP Address": "10.24.1.160",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "MAINTM1-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:02]",
    "Last Scanned": "17 Oct 2026 [12:22:47]",
    "MAC Address": "10-FF-E0-FD-88-6E",
    "Serial Number": "Default string",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "DESKTOP-8PESFRD",
    "IP Address": "192.168.1.15",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "WORKGROUP",
    "Group Name": "Micro-Tech Group->OpenAll",
    "User Name": "Admin",
    "Policy": "OpenAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [09:45:46]",
    "Last Scanned": "13 Nov 2026 [00:09:20]",
    "MAC Address": "40-B0-34-F5-0C-74",
    "Serial Number": "SGH824PXB1",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "QADU4-D1",
    "IP Address": "10.24.1.215",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "QAD4-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:50]",
    "Last Scanned": "31 Oct 2026 [12:33:18]",
    "MAC Address": "20-88-10-8A-36-7D",
    "Serial Number": "33M9S14",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PEDCORP-D1",
    "IP Address": "10.24.3.190",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PEDCORP-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:03]",
    "Last Scanned": "07 Nov 2026 [12:28:31]",
    "MAC Address": "64-00-6A-14-BD-71",
    "Serial Number": "3J4J882",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MARKETINGU1-L1",
    "IP Address": "10.24.1.220",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PURCHASE4-L1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [11:08:15]",
    "Last Connected": "12 Nov 2026 [18:08:06]",
    "Last Scanned": "31 Oct 2026 [12:34:40]",
    "MAC Address": "E4-A4-71-2E-B0-A3",
    "Serial Number": "3YL5LC2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MAINT3-D1",
    "IP Address": "10.24.3.96",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "MAINT3-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:55]",
    "Last Scanned": "01 Nov 2026 [00:59:57]",
    "MAC Address": "8C-EC-4B-60-4A-F2",
    "Serial Number": "1WXGGP2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "ACCOUNTS2-D1",
    "IP Address": "10.24.1.144",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "ACCOUNTS2-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:03]",
    "Last Scanned": "31 Oct 2026 [12:41:15]",
    "MAC Address": "50-9A-4C-38-D5-E7",
    "Serial Number": "8F7KZL2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MACHINESHOP3-D1",
    "IP Address": "10.24.3.55",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "MACHINESHOP3-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:03]",
    "Last Scanned": "31 Oct 2026 [12:26:29]",
    "MAC Address": "E4-54-E8-CD-9A-89",
    "Serial Number": "HBTRT23",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "DDP1-D1",
    "IP Address": "10.24.1.158",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "DDP-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "12 Nov 2026 [17:32:12]",
    "Last Scanned": "31 Oct 2026 [12:46:39]",
    "MAC Address": "64-00-6A-62-05-4A",
    "Serial Number": "F1K1N62",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "U4QADHEAD-L1",
    "IP Address": "10.24.1.53",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll_WhatsApp",
    "User Name": "U4QADHEAD-L1",
    "Policy": "BlockAll_WhatsApp",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:02]",
    "Last Scanned": "01 Nov 2026 [09:33:21]",
    "MAC Address": "F8-FE-5E-D6-2D-7E",
    "Serial Number": "5CD411JN3S",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "QUALITY-D1",
    "IP Address": "10.24.1.141",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "QUALITY-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:50]",
    "Last Scanned": "31 Oct 2026 [12:37:19]",
    "MAC Address": "98-90-96-C9-DB-B1",
    "Serial Number": "11WR542",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "ACCOUNTSU1-D1",
    "IP Address": "10.24.1.72",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "ACCOUNTS1-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [10:02:43]",
    "Last Scanned": "31 Oct 2026 [12:13:07]",
    "MAC Address": "9C-B1-50-44-90-35",
    "Serial Number": "CSY1P24",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "STORE4-D1",
    "IP Address": "10.24.1.153",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "STORES4-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:23]",
    "Last Scanned": "31 Oct 2026 [12:19:43]",
    "MAC Address": "20-88-10-6F-0A-0B",
    "Serial Number": "78YDWY3",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "COMMON3-D1",
    "IP Address": "10.24.1.213",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "GATE4-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [10:03:16]",
    "Last Scanned": "31 Oct 2026 [12:37:17]",
    "MAC Address": "98-90-96-C9-DB-51",
    "Serial Number": "80WR542",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PRODUCT1-QA",
    "IP Address": "10.24.1.181",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "U1PRODUCT-QA",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:01]",
    "Last Scanned": "31 Oct 2026 [13:11:53]",
    "MAC Address": "28-D0-43-E8-E3-BA",
    "Serial Number": "5CG4350C4X",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTGSAPSRVR",
    "IP Address": "10.24.1.30",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "Administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:18]",
    "Last Scanned": "-",
    "MAC Address": "00-15-5D-28-97-05",
    "Serial Number": "3527-8724-7566-7217-4907-0524-32",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2022 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "CORPMKT-L3",
    "IP Address": "10.24.3.133",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "CORPMKT-L3",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:01:55]",
    "Last Scanned": "31 Oct 2026 [12:37:51]",
    "MAC Address": "B0-C0-90-C6-78-28",
    "Serial Number": "3G695C2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "QADM1-D3",
    "IP Address": "10.24.1.183",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "QADM1-D3",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "12 Nov 2026 [18:55:20]",
    "Last Scanned": "31 Oct 2026 [12:13:43]",
    "MAC Address": "98-90-96-C9-DC-AD",
    "Serial Number": "2WVR542",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "QUALITY2-D1",
    "IP Address": "10.24.2.19",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll_WhatsApp",
    "User Name": "QUALITYU2-D1",
    "Policy": "BlockAll_WhatsApp",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:16]",
    "Last Scanned": "26 Aug 2026 [00:42:00]",
    "MAC Address": "E4-54-E8-C8-FF-3E",
    "Serial Number": "22XMB23",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MPIPL-D1",
    "IP Address": "192.168.1.33",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll_WhatsApp",
    "User Name": "MPIPL-D1",
    "Policy": "BlockAll_WhatsApp",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [09:50:46]",
    "Last Scanned": "13 Nov 2026 [00:16:49]",
    "MAC Address": "D0-46-0C-91-30-28",
    "Serial Number": "C1XXM24",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "CORPHRD-L3",
    "IP Address": "172.32.2.48",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "CORPHR-L3",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "12 Nov 2026 [18:31:12]",
    "Last Scanned": "31 Oct 2026 [14:48:47]",
    "MAC Address": "F8-FE-5E-D4-B8-D6",
    "Serial Number": "5CD411JN3Z",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PRODUCTION4-D2",
    "IP Address": "10.24.1.149",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PRODUCTION4-D2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:59]",
    "Last Scanned": "17 Oct 2026 [12:32:26]",
    "MAC Address": "8C-EC-4B-C7-AC-9B",
    "Serial Number": "92WS3W2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "CCTV",
    "IP Address": "192.168.0.4",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "WORKGROUP",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "Admin",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [09:50:46]",
    "Last Scanned": "07 Nov 2026 [12:21:39]",
    "MAC Address": "F4-8E-38-80-9B-05",
    "Serial Number": "BYX6B22",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTG-VM-PAY",
    "IP Address": "10.24.1.29",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "Administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:01:55]",
    "Last Scanned": "-",
    "MAC Address": "00-15-5D-28-97-02",
    "Serial Number": "7781-0753-7632-6411-2321-7826-70",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2022 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MPIPL-D3",
    "IP Address": "192.168.1.46",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MPIPL",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "MPIPL D3",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [09:50:46]",
    "Last Scanned": "07 Nov 2026 [12:17:49]",
    "MAC Address": "20-88-10-8F-9A-07",
    "Serial Number": "2PSBS14",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MPIPL1-L2",
    "IP Address": "192.168.1.39",
    "Endpoint Status": "Roaming",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->OpenAll",
    "User Name": "MPIPL-L2",
    "Policy": "OpenAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [10:00:49]",
    "Last Scanned": "24 Oct 2026 [17:12:13]",
    "MAC Address": "E4-0D-36-12-70-14",
    "Serial Number": "5CD337GTYS",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PURCHASE3-D1",
    "IP Address": "10.24.3.44",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Default",
    "User Name": "VOLVO-D1",
    "Policy": "Default_EPP",
    "Policy Status": "Not Published",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [11:08:15]",
    "Last Connected": "12 Nov 2026 [15:16:38]",
    "Last Scanned": "01 Aug 2026 [12:29:09]",
    "MAC Address": "E4-54-E8-CB-13-DA",
    "Serial Number": "CYLXJ23",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "QADM1-D2",
    "IP Address": "10.24.1.169",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "QADM1-D2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:58]",
    "Last Scanned": "31 Oct 2026 [12:13:46]",
    "MAC Address": "98-90-96-C9-D6-42",
    "Serial Number": "G1WR542",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "U1ENGINEERING-L1",
    "IP Address": "10.24.1.186",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "COPED-L1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [09:23:46]",
    "Last Scanned": "24 Oct 2026 [12:43:04]",
    "MAC Address": "28-D0-43-E8-E6-3A",
    "Serial Number": "5CG4350D0C",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTCNCSAPLIVE",
    "IP Address": "10.24.1.12",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "Administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:05]",
    "Last Scanned": "-",
    "MAC Address": "00-15-5D-BB-67-09",
    "Serial Number": "6302-7693-2157-8002-3280-4087-86",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2022 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "STORES2-D1",
    "IP Address": "10.24.2.37",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "STORESU2-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:34]",
    "Last Scanned": "31 Oct 2026 [12:26:01]",
    "MAC Address": "8C-EC-4B-AA-4A-DB",
    "Serial Number": "DQ3R6T2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "QAD4-D2",
    "IP Address": "10.24.1.178",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "QAD4-D2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:14]",
    "Last Scanned": "31 Oct 2026 [12:19:41]",
    "MAC Address": "20-88-10-AD-55-CD",
    "Serial Number": "GQJ9M24",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "AI-SYSTEM",
    "IP Address": "10.24.1.156",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->OpenAll",
    "User Name": "AISAP",
    "Policy": "OpenAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:21]",
    "Last Scanned": "13 Nov 2026 [00:43:01]",
    "MAC Address": "00-BE-43-8E-82-96",
    "Serial Number": "53C7SN3",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "HOME-MG",
    "IP Address": "192.168.1.132",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "WORKGROUP",
    "Group Name": "Micro-Tech Group->OpenAll",
    "User Name": "Admin",
    "Policy": "OpenAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [08:50:46]",
    "Last Scanned": "31 Oct 2026 [08:52:06]",
    "MAC Address": "08-8E-90-A0-09-6A",
    "Serial Number": "HHW7JK2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTG-VM-Veeam",
    "IP Address": "10.24.1.26",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:00]",
    "Last Scanned": "-",
    "MAC Address": "00-15-5D-28-97-06",
    "Serial Number": "2485-7875-8344-6686-2087-2501-69",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2022 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTG-MT-RDP1",
    "IP Address": "10.24.1.105",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->RDP Server",
    "User Name": "Administrator",
    "Policy": "RDP Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:25]",
    "Last Scanned": "-",
    "MAC Address": "00-15-5D-BB-67-05",
    "Serial Number": "0699-7101-1115-0567-6877-8057-25",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2016 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "ITSSRVR",
    "IP Address": "10.24.1.9",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "Administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:38]",
    "Last Scanned": "-",
    "MAC Address": "00-0C-29-1D-CF-38",
    "Serial Number": "VMware-56 4d 6a 7d cd 09 38 67-00 8d 18 df 5b 1d cf 38",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2016 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PPMC4-D1",
    "IP Address": "172.32.2.119",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PPMC4-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:07]",
    "Last Scanned": "31 Oct 2026 [12:13:37]",
    "MAC Address": "E8-CF-83-2F-B3-A1",
    "Serial Number": "GCX1P24",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "IT-Support",
    "IP Address": "10.24.1.98",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "Administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:22]",
    "Last Scanned": "-",
    "MAC Address": "CC-96-E5-38-FD-F1",
    "Serial Number": "9GHWMZ3",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2016 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "U3MFGHEAD-L1",
    "IP Address": "10.24.3.129",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll_WhatsApp",
    "User Name": "MFGHEADU3-L1",
    "Policy": "BlockAll_WhatsApp",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [11:08:15]",
    "Last Connected": "12 Nov 2026 [17:37:56]",
    "Last Scanned": "01 Oct 2026 [09:58:51]",
    "MAC Address": "9C-C7-D3-52-D4-00",
    "Serial Number": "5CG5343V7B",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PRODUCTION1-D2",
    "IP Address": "10.24.1.74",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->UnBlockUSB",
    "User Name": "PRODUCTION1-D2",
    "Policy": "UnBlockUSB",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:43]",
    "Last Scanned": "11 Nov 2026 [12:15:41]",
    "MAC Address": "9C-67-D6-54-3A-B2",
    "Serial Number": "6X22P24",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "AUDIT1-L1",
    "IP Address": "10.24.1.37",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Default",
    "User Name": "AUDIT-L1",
    "Policy": "Default_EPP",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [10:02:21]",
    "Last Scanned": "-",
    "MAC Address": "48-E2-44-2D-F2-AB",
    "Serial Number": "CND5464N6B",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "CORP-ITHEAD-L1",
    "IP Address": "10.24.1.31",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->OpenAll",
    "User Name": "CORPITHEAD-L1",
    "Policy": "OpenAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [11:08:15]",
    "Last Connected": "13 Nov 2026 [10:03:29]",
    "Last Scanned": "15 Oct 2026 [01:56:19]",
    "MAC Address": "D0-65-78-F2-AA-BC",
    "Serial Number": "5CD4297N1N",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": "\""
  }
];

// The PDFs stay beside the application files for a flat deployment. IIS rewrites
// root-level .pdf requests to authenticated API streaming instead of serving them statically.
// Department documents and circulars come from the shared folder (default \\172.32.2.12\Ftp).
// Each department page lists its own subfolder; the "All departments" board lists the
// whole share grouped by folder. Override in .env if the share or folder names change:
//   DEPT_DOCS_ROOT=\\172.32.2.12\Ftp
//   DEPT_DOCS_IT=IT  DEPT_DOCS_QUALITY=Quality  DEPT_DOCS_MARKETING=Marketing  DEPT_DOCS_HR=HR
// The Node service reads the share with its own Windows account, so that account needs read access.
const DEPARTMENT_DOCS_ROOT = (process.env.DEPT_DOCS_ROOT || '\\\\172.32.2.12\\Ftp').trim();
const DEPARTMENT_DOC_FOLDERS = {
  all: '',
  it: (process.env.DEPT_DOCS_IT || 'IT').trim(),
  quality: (process.env.DEPT_DOCS_QUALITY || 'Quality').trim(),
  marketing: (process.env.DEPT_DOCS_MARKETING || 'Marketing').trim(),
  hr: (process.env.DEPT_DOCS_HR || 'HR').trim()
};
const DEPARTMENT_DOC_TYPES = {
  '.pdf': 'application/pdf',
  '.doc': 'application/msword',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xls': 'application/vnd.ms-excel',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.ppt': 'application/vnd.ms-powerpoint',
  '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png'
};
const DEPARTMENT_DOC_MAX_DEPTH = 4;        // folder levels searched below a department folder
const DEPARTMENT_DOC_MAX_FILES = 3000;
const DEPARTMENT_DOC_CACHE_MS = 30000;
const departmentDocCache = new Map();
const departmentDir = (dept) => (Object.prototype.hasOwnProperty.call(DEPARTMENT_DOC_FOLDERS, dept)
  ? (DEPARTMENT_DOC_FOLDERS[dept] ? path.join(DEPARTMENT_DOCS_ROOT, DEPARTMENT_DOC_FOLDERS[dept]) : DEPARTMENT_DOCS_ROOT)
  : null);
const skipDocEntry = (name) => name.startsWith('.') || name.startsWith('~$') || /^(thumbs\.db|desktop\.ini)$/i.test(name);
async function listDepartmentFiles(baseDir, rel, depth, out) {
  const entries = await fs.promises.readdir(rel.length ? path.join(baseDir, ...rel) : baseDir, { withFileTypes: true });
  for (const entry of entries) {
    if (out.length >= DEPARTMENT_DOC_MAX_FILES) return;
    if (skipDocEntry(entry.name)) continue;
    if (entry.isDirectory()) {
      if (depth < DEPARTMENT_DOC_MAX_DEPTH) {
        try { await listDepartmentFiles(baseDir, rel.concat(entry.name), depth + 1, out); } catch (_) { /* unreadable subfolder */ }
      }
      continue;
    }
    const ext = path.extname(entry.name).toLowerCase();
    if (!entry.isFile() || !DEPARTMENT_DOC_TYPES[ext]) continue;
    try {
      const stats = await fs.promises.stat(path.join(baseDir, ...rel, entry.name));
      if (stats.size > 0) out.push({ path: rel.concat(entry.name).join('/'), name: entry.name, folder: rel.join(' / '), type: ext.slice(1), size: stats.size, modified: stats.mtime.toISOString() });
    } catch (_) { /* skip unreadable file */ }
  }
}
// Turns "Folder/Sub/File.pdf" into a full path inside baseDir, or null if it is not safe.
function resolveDepartmentFile(baseDir, relPath) {
  const parts = String(relPath || '').split('/');
  if (!relPath || relPath.length > 1000 || parts.length > DEPARTMENT_DOC_MAX_DEPTH + 1) return null;
  for (const part of parts) {
    if (!part || part === '.' || part === '..' || part.length > 255 || /[\\:*?"<>|\x00-\x1f]/.test(part) || skipDocEntry(part)) return null;
  }
  const full = path.join(baseDir, ...parts);
  const inside = path.relative(baseDir, full);
  if (!inside || inside.startsWith('..') || path.isAbsolute(inside)) return null;
  return DEPARTMENT_DOC_TYPES[path.extname(full).toLowerCase()] ? full : null;
}

// Circulars are stored only in the existing C:\server-plant\Circulars folders.
// Department folders are fixed server-side; the Canteen option is mapped to the
// deployment-provisioned `canteen` subfolder. Uploads never create or rename folders.
const CIRCULAR_ATTACH_ROOT = path.resolve('C:/server-plant/Circulars');
const CIRCULAR_CATEGORY_FOLDERS = Object.freeze({
  General: 'General',
  IT: 'IT',
  Quality: 'Quality',
  Marketing: 'Marketing',
  HR: 'HR',
  Canteen: 'canteen',
  Safety: 'Safety',
  Production: 'Production',
  Maintenance: 'Maintenance'
});
const CIRCULAR_CATEGORIES = Object.keys(CIRCULAR_CATEGORY_FOLDERS);
const CIRCULAR_DEPARTMENT_FOLDERS = Object.freeze([
  'Accounts', 'General', 'HR', 'IT', 'Maintenance', 'Marketing', 'canteen',
  'Production', 'Qms', 'Quality', 'Safety', 'Sales', 'Stores'
]);
const CIRCULAR_ATTACH_MAX = 20 * 1024 * 1024;
// First bytes of each allowed type, so a renamed .exe is refused.
const fileLooksLike = (ext, buf) => {
  const hex = buf.subarray(0, 8).toString('hex');
  if (ext === '.pdf') return buf.subarray(0, 5).toString('latin1') === '%PDF-';
  if (['.docx', '.xlsx', '.pptx'].includes(ext)) return hex.startsWith('504b0304');
  if (['.doc', '.xls', '.ppt'].includes(ext)) return hex.startsWith('d0cf11e0a1b11ae1');
  if (['.jpg', '.jpeg'].includes(ext)) return hex.startsWith('ffd8ff');
  if (ext === '.png') return hex.startsWith('89504e470d0a1a0a');
  return false;
};
const cleanFileName = (name) => path.basename(String(name || ''))
  .replace(/[\\/:*?"<>|\x00-\x1f]/g, ' ').replace(/\s+/g, ' ').replace(/^[.\s]+|[.\s]+$/g, '').slice(0, 120);

const PDF_DOCUMENTS = [
  'Approval Status of SAP-B1.pdf',
  'AP Account Payable.pdf',
  'AP Invoice.pdf',
  'AR Account  Payable.pdf',
  'AR Invoice.pdf',
  'BOM Approval.pdf',
  'Business Partner.pdf',
  'Complete Training Guide Payable Cycle.pdf',
  'complete Training Guide Receivable Cycle.pdf',
  'Customer Ageing Report.pdf',
  'Delivery Challan.pdf',
  'Delivery Note.pdf',
  'Goods Receipt PO.pdf',
  'Incoming Payment.pdf',
  'Inventory Counting.pdf',
  'Inventory Transfer Request.pdf',
  'Item Master.pdf',
  'MES  Web Application User Guide.pdf',
  'MES Dashboard - by Machine.pdf',
  'MES Dashboard - by OEE.pdf',
  'MES Dashboard - by Work Location.pdf',
  'MES Dashboard.pdf',
  'Micro Tech →Gate Application.pdf',
  'MIS Report.pdf',
  'Outgoing Payment.pdf',
  'Purchase Order.pdf',
  'Purchase Request.pdf',
  'Resource Master.pdf',
  'Sale Order.pdf',
  'SAP Dashboard All Module Comparision.pdf',
  'SAP Dashboard All Module.pdf',
  'SAP Dashboard Customer Aging Report.pdf',
  'SAP Dashboard Daily Trend.pdf',
  'SAP Dashboard Enquiry – Quotation.pdf',
  'SAP Dashboard Inventory Ageing.pdf',
  'SAP Dashboard RM Consumption.pdf',
  'SAP Dashboard Stock Report.pdf',
  'SAP Dashboard Vendor Aging Report.pdf',
  'SAP Dashboard.pdf',
  'Security Gate Inward Store Approval Procedure.pdf',
  'Security Gate Outward Procedure.pdf',
  'Security Gate Visiter Entry.pdf',
  'Store  Inward Procedure.pdf',
  'Store  Inward Quality Procedure.pdf',
  'Store  Outward Plant Head Approval Procedure.pdf',
  'Store  Outward Procedure.pdf',
  'Vender Ageing Report.pdf'
].map((name, index) => Object.freeze({ id: index + 1, name }));

// Kept for the separate HR policy panel; these entries are no longer in the
// SOP & Documents catalogue.
const HR_STATIC_DOCUMENTS = [
  { id: 6, doc_number: 'POL-HR-001', title: 'List of Holiday for 2026', category: 'HR', revision: 'F', updated_date: '2026-04-01', file_location: 'List of Holiday for 2026.pdf', pdf_url: '/api/hr/policy-pdf' }
];

function makeRateLimiter(maxRequests, windowMs) {
  const buckets = new Map();
  return (req, res, next) => {
    const now = Date.now();
    const key = req.socket.remoteAddress || 'unknown';
    let bucket = buckets.get(key);
    if (!bucket || now >= bucket.resetAt) {
      bucket = { count: 0, resetAt: now + windowMs };
      buckets.set(key, bucket);
    }
    if (buckets.size > 5000) {
      for (const [ip, value] of buckets) if (now >= value.resetAt) buckets.delete(ip);
      if (buckets.size > 5000) buckets.clear();
    }
    if (bucket.count >= maxRequests) {
      res.setHeader('Retry-After', String(Math.max(1, Math.ceil((bucket.resetAt - now) / 1000))));
      return res.status(429).json({ success: false, message: 'Too many attempts. Please try again later.' });
    }
    bucket.count += 1;
    next();
  };
}
const validText = (value, maxLength, allowEmpty = false) =>
    typeof value === 'string' && value.length <= maxLength && (allowEmpty || value.trim().length > 0);
const validEmail = (value, maxLength = 120) =>
    typeof value === 'string' && value.length <= maxLength && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
const validIsoDate = (value) =>
    typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) &&
    !Number.isNaN(Date.parse(value)) && new Date(value).toISOString().slice(0, 10) === value;
const validHttpUrl = (value) => {
  if (!validText(value, 255)) return false;
  try {
    const url = new URL(value);
    return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password;
  } catch {
    return false;
  }
};
const validRowId = (req, res, next, id) => {
  if (!/^[1-9]\d{0,9}$/.test(id)) return res.status(400).json({ success: false, message: 'Invalid record ID.' });
  next();
};
const nextId = (rows) => rows.reduce((max, item) => Math.max(max, Number(item.id) || 0), 0) + 1;

const EMPLOYEE_DETAILS_COLUMNS = ["S.No", "EmpNo", "EmpName", "Gender", "Martial Status", "DateOfBirth", "DateOfJoin", "Category", "Division", "Department", "Designation", "Section", "Grade", "Mobile No", "Watsapp No", "Emailid", "Aadhar No", "Voter ID", "Pan No", "Driving License No", "Ration Card No", "PassPort", "Account No", "Qualification", "Pre Company", "Pre Designation"];
const EMPLOYEE_DETAILS_DISPLAY_COLUMNS = EMPLOYEE_DETAILS_COLUMNS.filter((column) => !['Gender', 'Martial Status'].includes(column)).concat(['Gender', 'Martial Status']);
// Employee Details shows columns only up to Voter ID. Later columns (PAN, driving licence,
// ration card, passport, bank account, qualification, previous company and designation,
// gender, marital status) are never sent to the browser.
const EMPLOYEE_DETAILS_LAST_COLUMN = 'Voter ID';
EMPLOYEE_DETAILS_DISPLAY_COLUMNS.splice(EMPLOYEE_DETAILS_DISPLAY_COLUMNS.indexOf(EMPLOYEE_DETAILS_LAST_COLUMN) + 1);
// Also hidden on request: Section, Grade and Voter ID.
for (const column of ['Section', 'Grade', 'Voter ID']) {
  const at = EMPLOYEE_DETAILS_DISPLAY_COLUMNS.indexOf(column);
  if (at !== -1) EMPLOYEE_DETAILS_DISPLAY_COLUMNS.splice(at, 1);
}
// Aadhaar: only the last 4 digits leave the server, e.g. "XXXX XXXX 4510".
const maskAadhaar = (value) => {
  const digits = String(value == null ? '' : value).replace(/\D/g, '');
  if (digits.length < 4 || /^0+$/.test(digits)) return '';
  return 'XXXX XXXX ' + digits.slice(-4);
};
const EMPLOYEE_DETAILS_AADHAAR_POSITION = EMPLOYEE_DETAILS_DISPLAY_COLUMNS.indexOf('Aadhar No');
const EMPLOYEE_DETAILS_DISPLAY_INDEXES = EMPLOYEE_DETAILS_DISPLAY_COLUMNS.map((column) => EMPLOYEE_DETAILS_COLUMNS.indexOf(column));
const EMPLOYEE_DETAILS_SOURCE = [

  ["8","9999","RAVI","Male","single","1965-05-10","2023-06-01","DIRECTOR","UNIT 1","DIRECTOR","EXECUTIVE DIRECTOR","ADMIN STAFF","COMMON","","","","","0","0","0","","0","0","","",""],
  ["9","10000101","MURALI BABU G","Male","married","1962-05-09","1995-04-01","DIRECTOR","UNIT 1","DIRECTOR","DIRECTOR","ADMIN STAFF","COMMON","9487800101","","muralibabu@microtechcnc.in","978304530700","0","AECPB6772N","","","0","15601012649","","",""],
  ["10","10000102","JOHNSON PAUL P","Male","married","1964-03-09","1995-04-01","DIRECTOR","UNIT 1","DIRECTOR","DIRECTOR","ADMIN STAFF","COMMON","","","johnsonpaul@microtechcnc.in","804313962918","0","AFSPP9755N","","","0","15601012583","","",""],
  ["11","10000103","SARASWATHI M","Male","married","1969-03-18","2019-04-01","DIRECTOR","UNIT 1","DIRECTOR","MANAGER","ADMIN STAFF","COMMON","","","muralibabu@microtechcnc.in","845494316346","0","BXVPS2013L","","","0","147001001817087","","",""],
  ["12","10000104","IRENE PAUL P","Female","married","1970-05-31","2019-04-01","DIRECTOR","UNIT 1","DIRECTOR","MANAGER","ADMIN STAFF","COMMON","","","johnsonpaul@microtechcnc.in","","0","ABCPI4853J","","","0","299053000014837","","",""],
  ["13","10000106","VIGNESH MURALIBABU","Male","single","1996-10-30","2019-10-01","MANAGEMENT","UNIT 1","MANAGEMENT","VICE PRESIDENT","ADMIN STAFF","COMMON","9487003102","","mvignesh1996@gmail.com","916281802306","0","BUDPV1318J","TN7020140009244","","0","50100272029141","","",""],
  ["14","10000107","JOSEPAUL JOHNSON","Male","single","1994-06-12","2022-09-01","MANAGEMENT","UNIT 1","MANAGEMENT","VICE PRESIDENT","ADMIN STAFF","COMMON","","","","804313962918","0","0","0","","0","0","","",""],
  ["15","11100281","NARASIMMAN L","Male","married","1973-05-21","2025-01-24","MANAGEMENT","UNIT 1","MANAGEMENT","CHIEF EXECUTIVE OFFICER","ADMIN STAFF","COMMON","9741785851","9741785851","narasimman.l@microtechcnc.in","543430021768","0","0","0","","0","0","","",""],
  ["16","11100364","DEEPTHI MURALIBABU","Female","single","1999-02-08","2026-02-17","MANAGEMENT","UNIT 1","MANAGEMENT","VICE PRESIDENT","ADMIN STAFF","COMMON","","","","","0","0","0","","0","0","","",""],
  ["17","99900011","PRABHU","Male","married","1983-07-22","2025-09-01","MANAGEMENT","UNIT 1","MANAGEMENT","GENERAL MANAGER","ADMIN STAFF","COMMON","8669682255","8669682255","prabhu.jayaraman83@gmail.com","215227217552","0","AJMPJ6085B","TN24Z2008004654","","0","0","BSC - Applied Science and Computer Technology, Supply Chain Management - IIMK","BARCLAYS SINGAPORE, WRIGLEY , UNISOFT , BARCLAYS , TETRAPAK","DELIVERY LEAD, SAP TECHINCAL LEAD, SAP CONSULTANT, AVP, FUNCTIONAL LEAD"],
  ["18","11000005","MURUGAN D","Male","married","1970-06-01","2001-02-12","CORP","UNIT 1","FINANCE","SENIOR OFFICER","ADMIN STAFF","COMMON","9487800112","","dmurugansp@gmail.com","905741253760","0","BVGPM3297M","","","0","147001000430568","","",""],
  ["19","11000014","THYAGARAJULU N","Male","married","1981-06-07","2006-10-16","CORP","UNIT 1","PURCHASE","SENIOR MANAGER","ADMIN STAFF","COMMON","9487800113","","rajulu1981@gmail.com","798852015114","0","AJGPT1929E","","","0","147001000508616","B.COM","M/S NAIDU & RAO, FIEM INDUSTRIES","AUDIT ASST, PURCHASE ASST"],
  ["20","11000021","MADESH K M","Male","married","1989-05-04","2007-11-19","CORP","UNIT 1","MAINTENANCE","MANAGER","ADMIN STAFF","COMMON","9442254110","","madeshmicrotech@gmail.com","892860682036","0","EHSPM1369D","TN7020160010138","","0","147001000532884","HSC","J.R. PACKAGE LTD","HELPER"],
  ["21","11000024","VIJAYA RANI S","Female","married","1983-02-10","2009-11-06","CORP","UNIT 1","HUMAN RESOURCE & ADMIN","EXECUTIVE","ADMIN STAFF","COMMON","8072993683","8072993683","vijayarani10021980@gmail.com","862187028303","0","RMWPV3664P","TN70 2018 0006673","","0","147001001169720","SSLC","46519, ESSAAR TOOLS , MICRO TECH CNC PRESSINGS INDIA PVT LTD","OIJIO, ACCOUNTS ASST, HR DEPARTMENT"],
  ["22","11000028","RAMESH C","Male","married","1978-06-25","2015-06-16","CORP","UNIT 1","NPD","ASSISTANT GENERAL MANAGER","ADMIN STAFF","COMMON","9843861320, 7904563522","","rameshmechcnc@gmail.com","932556770489","0","APKPR3438N","TN2919970002331","","0","147001000470281","ITI, DME","MARKS ENGG WORKS, SOUTHERN ACCESSORIES PVT LTD, GLOBE INDUSTRIAL COMPONENTS, MICRO TECH CNC PVT LTD","CNC OPERATOR & SETTER, VMC & HMC SUPERVISIOR & CNC PROGARAMER, SUPERVISIOR & CNC PROGARAMER, VMC & HMC SUPERVISIOR & CNC PROGARAMER"],
  ["23","11000031","VINOTHKUMAR P","Male","married","1991-01-26","2015-09-21","CORP","UNIT 1","DESIGN","MANAGER","ADMIN STAFF","COMMON","9443171724","9443171724","vinog1991@gmail.com","580516674138","0","AQQPV0487J","TN5420090006412","","0","189001001127502","DIPLOMA, BE","GEN CAD TECHHNOLOGY","DESIGN ENGINEER"],
  ["24","11000034","SELVARAJ A","Male","married","1981-05-10","2016-05-03","CORP","UNIT 1","INFORMATION TECHNOLOGY","ASSISTANT GENERAL MANAGER","ADMIN STAFF","COMMON","9994781322","9994781322","sbsselvaraja@gmail.com","855198174510","ZBC0827048","BKUPS2037J","TN29Y20010001249","","J8547676","500101010912226","DIPLOMA IN COMPUTER TECHNOLOGY","INDIAN COMPUTER CORPORATION, HEMA ENGG INDS LTD","SYSTEM ADMININISTRATOR, EXECUTIVE - EDP"],
  ["25","11000035","GANESA SUBRAMANIAN G V","Male","married","1971-05-22","2016-05-19","CORP","UNIT 1","FINANCE","GENERAL MANAGER","ADMIN STAFF","COMMON","9443292378","9677952712","gvgmani2010@gmail.com","246759981911","0","AJCPG9547P","","","0","500101010912253","MBA FINANCE MANAGEMENT, BCOM","FIRST GARMENT MANUFACTURING CO. PVT LTD, THAI SUMMIT NEEL AUTO PVT LTD, MICRO FINE PRODUCTS, SOUTHERN RIMS PRIVATE LTD, TOWER STEELS INDIA LTD, RAJSRIYA AUTOMOTIVE INDUSTRIES PVT LTD, DHANYAS PVT LTD","ACCOUNTS OFFICER, ASST. MANAGER, ACCOUNTANT, ACCOUNTANT, CHIEF ACCOUNTANT, MANGER - FINANANCE, GENERAL MANAGER"],
  ["26","11000058","ROHINI RAMANATHAN","Female","married","1988-10-12","2019-01-02","CORP","UNIT 1","ADMINISTRATION","COMPANY SECRETARY","ADMIN STAFF","COMMON","7871965234","","ramanathan.rohini@gmail.com","470212371078","0","AQMPR4874R","TN7020090005402","","0","500101012061290","BCOM, MCOM, ACS","SPEL SEMICONDUCTOR LTD, MSM MICROFINANCE LTD","EXECUTIVE & COMPANY SECRETARY, COMPANY SECRETARY"],
  ["27","11000065","VIGNESH D N","Male","single","1997-03-15","2020-08-06","CORP","UNIT 1","MARKETING","DEPUTY MANAGER","ADMIN STAFF","COMMON","8220729970","","dnvignesh4@gmail.com","571301765438","0","CUVPD8759A","","","0","500101012427367","DME, POST DIPLOMA IN TOOL DESIGN","AVTEC LTD","TOOL ENGINEER"],
  ["28","11100028","SANTHOSH RAO S","Male","married","1988-05-06","2022-12-26","CORP","UNIT 1","PURCHASE","EXECUTIVE","ADMIN STAFF","COMMON","9444484213","","santhoshrao009@gmail.com","856858774450","0","ERGPS7599M","0","","0","500101012591063","SSLC, 12 th","KARNATAKA TURNEED COMPONUTS P LTD, SUPREME LTD","OPERATOR, EXECUTIVE"],
  ["29","11100237","VINODH KUMAR S","Male","single","1992-12-21","2024-08-29","CORP","UNIT 1","FINANCE","OFFICERS","ADMIN STAFF","COMMON","9980222987","9980222987","mremailid2112@gmail.com","634288951329","0","BBWPV0123K","0","","0","500101013986446","","FREEDO OPTHALMIC PVT LTD","ASST"],
  ["30","11100246","MAGESH KUMAR S","Male","single","1978-08-05","2024-10-03","CORP","UNIT 1","MARKETING","ASSISTANT MANAGER","ADMIN STAFF","COMMON","9886869015","9886869015","samagesh@gmail.com","392945306828","0","CHCPS1562C","0","","0","500101014035639","B.E","SOUTH INDIA ENGG WORKS, MAINI PERCISION PRODUCTS LTD, RANGSONS AERO, SANSARA AERASPACE LTD","ENGG, SENIOR ENGG, ASSOCIATE ENGG, SENIOR ENGG"],
  ["31","11100258","PRAMOTH KUMAR S","Male","married","1995-06-07","2024-11-04","CORP","UNIT 1","DESIGN","SENIOR ENGINEER","ADMIN STAFF","COMMON","8438385226","8438385226","pramothpradeep07@gmail.com","704872098577","0","DQXPP1243Q","0","","0","500101013719447","B.E","OMMI FORGE P LTD, INNOFORGE P LTD, BANSAL PRECISION FORGE","ENGG, SENIOR ENGG, SR ENGG"],
  ["32","11100289","THENMOZHI S","Female","single","2001-03-13","2025-05-06","CORP","UNIT 1","QUALITY","ENGINEER","ADMIN STAFF","COMMON","8925091124","8925091124","thenivasu2001@gmail.com","351548767430","0","OEEPS3360K","0","","0","500101014209923","BE","CIE HOSUR LTD","WXECUTIVE"],
  ["33","11100291","VIGNESH G B","Male","single","2003-06-17","2025-06-02","CORP","UNIT 1","FINANCE","EXECUTIVE","ADMIN STAFF","COMMON","8248488606","8248488606","vickygb2003@gmail.com","551609568544","0","CESPV3323K","0","","0","500101014209939","B ACHELOR OF ARTS","COPRAL ENGG","ACCOUNTS ASSISTANT"],
  ["34","11100292","SHARANKUMAR KRISHNAMOORTHY","Male","single","1997-12-27","2025-06-02","CORP","UNIT 1","DESIGN","JUNIOR ENGINEER","ADMIN STAFF","COMMON","8248691557","8248691557","sharankumar042@gmail.com","209613296795","0","JFDPK6335B","0","","0","500101014209940","B E","PRO M MACHINING SOLUTIONS INDIA P LTD","MEMBER - DESIGN"],
  ["35","11100293","MANUKUMAR T M","Male","married","1986-01-20","2025-06-11","CORP","UNIT 1","PROCESS ENGINEERING","SENIOR MANAGER","PRODUCTION","COMMON","9035913653","9035913653","MANUKUMARTM@GMAIL.COM","745510683342","ZBC3892635","BLQPM1912D","TN24Z20080005285","","0","500101014209954","DME","SPICER INDIA LTD, CIE AUTOMOTIVE INDIA LTD","TEAM LEADER, DEPUTY MANAGER"],
  ["36","11100309","NAVEEN TILAK H G","Male","single","1994-11-04","2025-07-02","CORP","UNIT 1","MARKETING","SENIOR MANAGER","ADMIN STAFF","COMMON","8722713307","8722713307","naveentilak04@gmail.com","960736117740","NMD3490364","BIPPN0552G","KA1320130011618","","T5729151","500101014312769","B.E","CIE INDIA","DEPUTY MANAGER"],
  ["37","11100338","PURUSHOTHAM A ATHNI","Male","single","1994-05-21","2025-11-12","CORP","UNIT 1","MARKETING","DEPUTY MANAGER","ADMIN STAFF","COMMON","9035315861","9035315861","purushothamhsn26@gmail.com","984705783145","0","DXCPP5277A","KA1320130011679","","Z8147734","500101014321725","B.E","STUMPP, SCHUELE, KMF, CIF, CIE","ENGINEER, TECHNICAL OFFICER, EXECUTIVE, ENGINEER"],
  ["38","11100345","RAMESH D","Male","single","2006-04-14","2025-12-17","CORP","UNIT 1","NPD","TRAINEE","ADMIN STAFF","COMMON","9384911897","9384911897","rameshdharmaraj447@gmail.com","582701536193","0","0","0","","0","500101014501716","DME","PROTECH ENGG SERVICE","DESINEER"],
  ["39","11100363","CHIRANJEEVI YELLACHARY","Male","single","2002-02-17","2026-02-09","CORP","UNIT 1","PROCESS ENGINEERING","ENGINEER","PRODUCTION","COMMON","9025981587","9025981587","chiruvishvabramin22@gmail.com","206012546982","0","CGTPC7079L","0","","0","500101014313040","ITI, D M E","ASHOK LEYLAND, TEAL (TITAN), GLOBAL CLACIUM","APPRENTICE, CL, ASSOITE"],
  ["40","11100387","SURENDRAN R","Male","single","1991-05-04","2026-06-10","CORP","UNIT 1","FINANCE","ASSISTANT MANAGER","ADMIN STAFF","COMMON","","","","932041016509","0","0","0","","0","500101014644048","","",""],
  ["41","11100436","RAJAMANI HARIKRISHNAN","Male","single","2001-04-24","2026-07-22","CORP","UNIT 1","FINANCE","EXECUTIVE","ADMIN STAFF","COMMON","","","","502565226126","0","0","0","","0","500101014644065","","",""],
  ["42","11100459","MATHAIYAN AYYANDURAI","Male","married","1982-05-20","2026-09-09","CORP","UNIT 1","QUALITY","DEPUTY GENERAL MANAGER","ADMIN STAFF","COMMON","7259753232","7259753232","mathaiyan1205@gmail.com","760302311120","0","AWFPM6563P","0","","0","0","B.E, M.S","NEXTEER AUTO MOTIVE, GKN DRIVELINE, CIE AUTO MOTIVE","MANAGER, ASST MANAGER, HEAD QUALITY"],
  ["43","11100464","DHANDABANI S","Male","single","1983-11-17","2026-10-12","CORP","UNIT 1","HUMAN RESOURCE & ADMIN","MANAGER","ADMIN STAFF","COMMON","","","","281095347226","0","0","0","","0","0","","",""],
  ["44","22000004","RAMAMOORTHY R","Male","married","1975-02-02","1997-12-02","CORP","UNIT 1","PURCHASE","SENIOR MANAGER","ADMIN STAFF","COMMON","9487800106","","sourcing@microtechcnc.in","300201599370","0","ARKPR7236E","","","0","147001000430565","HSC","",""],
  ["45","33005209","SATHISHKUMAR G","Male","single","1996-06-02","2019-05-30","CORP","UNIT 1","MARKETING","ENGINEER","PRODUCTION","COMMON","8695947037","","gsathishk4@gmail.com","497750533320","0","FTPPS9762A","","","0","500101010821123","DIPLOMA MECH, HSC","SAMRAJ ENGINEERING CONTROLS PVT LTD, SAMRAJ ENGINEERING CONTROLS PVT LTD, ACCUCUT LASERS","LASER CUTTING OPERATOR PROGRAMMER & SUPERVISOR, LASER CUTTING OPERATOR, LASER CUTTING OPERATOR"],
  ["46","11000006","ASHOK D","Male","married","1982-03-01","2003-02-05","STAFF","UNIT 1","QUALITY","ENGINEER","ADMIN STAFF","AUTOMOTIVE","9487800116","","ashokdeva1982@gmail.com","543232691232","0","ANJPA1026C","","","0","147001000517720","ITI","TVS MOTOR COMPANY","FACTORY PRODUCTION"],
  ["47","11000008","SABASTIN S","Male","married","1982-10-02","2004-02-01","STAFF","UNIT 1","VMC MACHINE SHOP","ASSISTANT MANAGER","PRODUCTION","COMMON","9600857197","","sseba3786@gmail.com","335070247497","0","FVJPS2376J","","","0","147001000517728","SSLC, HSC","MICRO TECH CNC PVT LTD","OPERATOR"],
  ["48","11000009","KUMAR R","Male","married","1979-07-05","2004-03-18","STAFF","UNIT 1","VMC MACHINE SHOP","DEPUTY MANAGER","PRODUCTION","COMMON","9442233770","","hrd-unit1@microtechcnc.in","790768747632","0","CNNPK1476L","","","0","147001000432717","ITI TURNER","ASHOK LEYLAND PHASE - II, CARBORUNDUM UNIVERSAL, ASHOK LEYLAND PHASE - II","TEMPMRORY WORKMAN, CNC MACHINE OPERATOR, APPRENTICE"],
  ["49","11000011","GURUNATHAN D","Male","married","1986-03-07","2005-08-16","STAFF","UNIT 1","VMC MACHINE SHOP","ASSISTANT MANAGER","PRODUCTION","COMMON","9629728289","","gurunathan86.d@gmail.com","930448264962","0","BFYPG8941N","TN7020140009339","","0","147001000532880","DEEE","",""],
  ["50","11000012","GOVINDARAJU K","Male","married","1971-05-10","2006-07-01","STAFF","UNIT 1","CNC MACHINE SHOP","ASSISTANT MANAGER","PRODUCTION","COMMON","9442232129","","k.roshinimani@gmail.com","504003667114","0","AVUPG5191M","","","0","147001000517725","SSLC","EASWARI ENGG","PRODUCTION INCHARGE"],
  ["51","11000015","DHUGARAM S","Male","married","1985-04-26","2006-11-29","STAFF","UNIT 1","OPERATIONS","ASSISTANT GENERAL MANAGER","ADMIN STAFF","COMMON","9487800120","","thukka.rao@gmail.com","472229170918","0","APPPD7594E","","","0","147001000508629","DEEE","EXIDE INDUSTRIES","DME APPENTICE"],
  ["52","11000019","CHINNASAMY M","Male","married","1972-04-20","2007-07-12","STAFF","UNIT 1","CNC MACHINE SHOP","ENGINEER","PRODUCTION","AUTOMOTIVE","9952679684","","hrd-unit1@microtechcnc.in","560489846461","0","","","","0","147001000541796","ITI","DITAMARY HYCON LTD, CHEMPLAST SANMAR LTD, INTERFIT TECHNO PRODUCTS, MICRO TECH CNC PVT LTD","WORKERS TURNER, MAINTEANCE, CNC TURNER, CNC TURNING OPERATOR"],
  ["53","11000022","KARTHICK R","Male","married","1989-05-03","2007-11-28","STAFF","UNIT 1","CNC AEROSPACE","ASSISTANT MANAGER","PRODUCTION","COMMON","9047069308","","karthick6861@gmail.com","354297631106","0","CRVPK3640J","","","0","147001000541323","ITI","",""],
  ["54","11000023","SUBRAMANI N","Male","married","1985-05-18","2008-04-18","STAFF","UNIT 1","CNC AEROSPACE","ASSISTANT MANAGER","PRODUCTION","COMMON","8940436637","8940436637","subramanisubramani62052@gmail.com","660358161660","0","BEMPN4159L","","","0","147001000540859","ITI TURNER","BIMETAL BEARING LIMITED, BALAJI ENGG","TURNER, CNC TURNING"],
  ["55","11000042","VENKATESA MOORTHY C","Male","married","1988-05-30","2017-09-01","STAFF","UNIT 1","CONVENTIONAL","SENIOR ENGINEER","PRODUCTION","COMMON","9942047646","","cvenkatesmurthy@gmail.com","988147611422","0","BDXPV678AM","TN7020170008914","","0","500101011542279","10TH, DCA","",""],
  ["56","11000045","PRAKASH K","Male","married","1983-05-05","2017-11-25","STAFF","UNIT 1","VMC MACHINE SHOP","SENIOR ENGINEER","PRODUCTION","COMMON","9677899771","","kprakashsuji@gmail.com","276099333864","0","DGOPP5927C","","","0","500101011587561","DME","ESSAE DIGITRONIC PVT LTD, ESSBEE PRECISION PVT LTD, KANDHI PERECISION PVT LTD, KARANATAKA TURN COMPONENTS","SHIFT INCHARGE, SETTER & OPERATOR, OPERATOR, OPERATOR"],
  ["57","11000053","LOGATHIBAN K","Male","single","1991-06-12","2018-05-28","STAFF","UNIT 1","PPC","ASSISTANT MANAGER","ADMIN STAFF","COMMON","9677489703","","logathiban26@gmail.com","823213939974","0","AEGPL9556G","TN2520120005077","","0","500101011580272","MCA, BCA","SHIBSI TECHNOLOGIES","DESKTOP ENGINEER"],
  ["58","11000069","KANNADHASAN K","Male","single","1994-09-28","2021-03-10","STAFF","UNIT 1","STORES","ASSISTANT MANAGER","ADMIN STAFF","COMMON","9677695281","","kannadhasan94@gmail.com","554347519409","0","ENEPK1371R","TN70 20170000835","","0","500101012603327","BSC","HEMA ENGG INDUSTRIES LTD","IT EXECTIVE"],
  ["59","11000079","SIVA R","Male","married","1982-12-05","2022-04-25","STAFF","UNIT 1","PPC","ASSISTANT MANAGER","ADMIN STAFF","COMMON","9842163424","","rsiva82@gmail.com","624566685460","0","0","0","","0","500101013163478","HSC, BE","FOXCONN INDIA PVT LTD, DYNATRONIX INDIA PVT LTD","PRODUCTION ENGINEER, PRODUCTION & MARKETING MANAGER"],
  ["60","11001009","RAMESH S","Male","married","1985-04-02","2006-04-24","STAFF","UNIT 1","VMC MACHINE SHOP","SENIOR ENGINEER","PRODUCTION","HYDRALIC","8754291131","","rameshsaran994@gmail.com","875805430687","0","ELQPS1829Q","IndiaF/TN/25/00276/2004","","0","147001000531964","DEEE","",""],
  ["61","11001011","SAKTHI M","Male","married","1986-04-10","2006-08-08","STAFF","UNIT 1","QUALITY","ASSISTANT ENGINEER","ADMIN STAFF","HYDRALIC","9042387447","","sakthi.sandhya1994@gmail.com","923705776149","0","DZDPS1389K","TN7020150008710","","0","147001000494764","HSC","",""],
  ["62","11001027","MUNIRAJ M","Male","married","1986-05-01","2008-01-05","STAFF","UNIT 1","STORES","JUNIOR OFFICER","","COMMON","9994081314","","stores-unit1@microtechcnc.in","686223722430","0","ILVPM4630J","","","0","500101010677025","HSC","",""],
  ["63","11001033","PRASANNA KUMAR S","Male","married","1991-05-23","2010-01-10","STAFF","UNIT 1","CONVENTIONAL","SENIOR SUPERVISOR","PRODUCTION","COMMON","9585613143","","chrankumar257233@gmail.com","439925982652","0","","","","0","147001001333132","ITI","",""],
  ["64","11001036","VISWANATHAN M","Male","married","1986-11-09","2010-11-07","STAFF","UNIT 1","QUALITY","SENIOR ENGINEER","ADMIN STAFF","COMMON","7539940011","","vishwanathansala@gmail.com","592521371684","0","","","","0","147001000851138","DME","",""],
  ["65","11001059","MUBARAK S","Male","married","1992-04-05","2012-02-25","STAFF","UNIT 1","CONVENTIONAL","SUPERVISOR","PRODUCTION","COMMON","9750786340, 9894505723","","mubaraksmk62@gmail.com","565099952406","0","","","","0","147001001333151","HSC","FLEETGUARD","FABRICATION LINE OPERATOR"],
  ["66","11001105","MUNIRAJ S","Male","single","1991-11-01","2015-08-19","STAFF","UNIT 1","CNC MACHINE SHOP","ASSISTANT ENGINEER","PRODUCTION","COMMON","8754134363","","munirajmuni377@gmail.com","719138689443","0","","","","0","500101010750216","DME","SHARDLOW INDIA LTD","JR. MANAGEMENT TRAINEE"],
  ["67","11001114","BALAKANNAN S","Male","single","1995-07-28","2015-12-02","STAFF","UNIT 1","QUALITY","SENIOR ENGINEER","ADMIN STAFF","COMMON","9159433913","","balakannan0414@gmail.com","386545917106","0","","","","0","147001002127849","DME","",""],
  ["68","11001125","AKASH V","Male","single","1995-06-12","2016-06-06","STAFF","UNIT 1","CNC AEROSPACE","ENGINEER","PRODUCTION","COMMON","7094084787","","akashmech111@gmail.com","695570808366","0","CTPPA7395J","","","0","500101010983473","BE","",""],
  ["69","11001133","KALAIARASAN G","Male","single","1993-08-02","2016-06-13","STAFF","UNIT 1","TOOL ROOM","SENIOR ENGINEER","PRODUCTION","COMMON","9361576724","","kalaiguna93@gmail.com","969143366314","0","EBTPK3720H","TN7020180006910","","0","500101010912227","BE- MECH","",""],
  ["70","11001243","ASHOK KUMAR R","Male","married","1982-05-28","2017-09-04","STAFF","UNIT 1","MAINTENANCE","ASSISTANT MANAGER","ADMIN STAFF","COMMON","9789536453","","ashokkns007@gmail.com","300875542988","0","BNFPA5523D","","","0","500101011542162","BE - EEE","SODEXO TECHNICAL SERVICE IND PVT LTD, GRAVITY INDIA TECHNOLOGIES","SENIOR FACILITY TEAM MEMBER, BUSINESS DEVELOPMENT OFFICER"],
  ["71","11001260","KRISHNAMOORTHY N","Male","single","1994-06-16","2017-09-01","STAFF","UNIT 1","QUALITY","ASSISTANT MANAGER","ADMIN STAFF","HYDRALIC","7904903428","","krishmurthy29@gmail.com","474278438616","0","BWOPN0353A","TN7020170000254","","0","500101011600563","HSC, DME","",""],
  ["72","11001445","ANBARASU S","Male","married","1991-06-30","2018-06-04","STAFF","UNIT 1","QUALITY","SENIOR ENGINEER","ADMIN STAFF","ELECTRIC VEHICLE","9789921435","","anbumech30@gmail.com","769977105889","0","BDUPA8729E","","","0","500101011867729","BE MECH, DME","LUK INDIA PVT LTD","ASSEMBLY DEPARTMENT"],
  ["73","11001501","AJITHKUMAR M","Male","single","1995-12-13","2018-08-27","STAFF","UNIT 1","QUALITY","ENGINEER","ADMIN STAFF","COMMON","9092275652","","ajith.95.hsr@gmail.com","381618013098","0","HKEM1634P-","","","0","500101012061292","BE- MECH","",""],
  ["74","11001665","AJITH A","Male","single","1998-05-26","2022-06-06","STAFF","UNIT 1","STORES","JUNIOR OPERATING ENGINEER","ADMIN STAFF","COMMON","9344208523","","ajith26598india@gmail.com","581484202351","0","CPHPA8476E","0","","0","500101013185883","BSC","FLEETGUARD FILTERS P LTD","STORE"],
  ["75","11100001","JAGADEESAN K S","Male","single","1991-06-29","2022-11-01","STAFF","UNIT 1","MAINTENANCE","ENGINEER","ADMIN STAFF","COMMON","9003678867","","jaganmech01@gmail.com","301190017192","0","0","0","","0","500101012720046","B E MECH","TVS SERVICE CENTRE, GENCAD TECHNOLOGY, FINE METAL STAMPING, LIC, GENCAD TECHNOLOGIES, HYUNDAI, BAJAJ","ASSIS TECHNICIAN, MARKETING AND FOLLOW, QUALITY ENGG, DEVELOPMENT OFFICER, TECHNICAL ENGINEER, ASSIS TECHNICIAN, TECHNICIAN"],
  ["76","11100029","SUNIL KUMAR K","Male","married","1988-05-20","2023-02-13","STAFF","UNIT 1","WIRE ELECTRICAL DISCHARCHABLE MACHINE","SENIOR ENGINEER","PRODUCTION","ELECTRONICS","8546858379","","suni9009kumar@gmail.com","987944520798","0","BNOPK3567N","0","","0","500101013371884","ITI FITTER","PRECISION TOOL AND IMPLEMENT P LTD, CON CAM TECHNOLOGY P LTD, ANANTH WIRETECH TOOLING , LAKSHMI INDUSTRIES AND ENTERPRISES","WIRE CUT OPERATOR CUM PROGEAMMER 0 , WIRE CUT OPERATOR CUM PROGEAMMER, WIRE CUT OPERATOR CUM PROGEAMMER, WIRE CUT OPERATOR CUM PROGEAMMER"],
  ["77","11100290","SEKAR M","Male","single","1999-03-25","2025-05-06","STAFF","UNIT 1","MAINTENANCE","JUNIOR ENGINEER","ADMIN STAFF","COMMON","6385465575","6385465575","sekar2531999@gmail.com","527985372433","0","MJXPS4041P","0","","0","500101014209902","","",""],
  ["78","11100376","PREM KUMAR P","Male","single","1995-06-03","2026-05-25","STAFF","UNIT 1","MAINTENANCE","JUNIOR ENGINEER","ADMIN STAFF","COMMON","","","","928901146705","0","0","0","","0","500101014394028","","",""],
  ["79","11100467","FAZULUDEEN F","Male","single","2005-05-21","2026-10-29","STAFF","UNIT 1","NPD","GET","ADMIN STAFF","COMMON","7904141273","","","795881218289","0","AJJPF6947M","TN3320240002375","","0","0","","",""],
  ["80","22002014","VIGNESH PAVITHRAN","Male","single","1996-04-10","2020-08-19","STAFF","UNIT 1","QUALITY","ASSISTANT MANAGER","ADMIN STAFF","COMMON","8608289498","","vikivigneshbharath@gmail.com","647563776133","0","AVGPV5331A","","","0","500101012427370","BTech","GET CHENNAI","QUALITY ENGINEER"],
  ["81","22003014","KARTHI A","Male","single","1991-06-02","2020-07-06","STAFF","UNIT 1","QUALITY","SENIOR ENGINEER","ADMIN STAFF","COMMON","9500470161","","karthikmech065@gmail.com","897236177790","0","DNRPK9613Q","","","0","500101012427361","DME, BE, 10TH","ESSAE DIGITRONICS PVT LTD, KAY JAY FORGING PVT LTD","QUALITY ENGINEER, QUALITY EXECUTIVE"],
  ["103","11001002","MURUGAN S","Male","married","1975-06-15","1995-02-11","WORKER","UNIT 1","VMC MACHINE SHOP","SENIOR OPERATOR","PRODUCTION","HYDRALIC","9942072934","","sreesubhan2014@gmail.com","669548069001","0","BLJPM4502L","TN24Z20070006651","","0","147001000519866","ITI FITTER","ITI FITTER","78"],
  ["104","11001003","SURESH D","Male","married","1983-06-02","2002-12-11","WORKER","UNIT 1","VMC MACHINE SHOP","SENIOR OPERATOR","PRODUCTION","ELECTRIC VEHICLE","9629487408","","suresh.micro728@gmail.com","583200491818","0","GNNPS2432C","TN7020150003362","","0","147001000432718","SSLC","",""],
  ["105","11001005","PERUMALDASS R","Male","married","1976-01-20","2003-09-24","WORKER","UNIT 1","STORES","STORES ASSISTANT","ADMIN STAFF","COMMON","9585168310","","perumaldass1234@gmail.com","962656079473","0","FCFPP0953K","","","0","147001000508612","HSC","",""],
  ["106","11001006","ASHOK KUMAR Y","Male","married","1983-03-07","2003-10-01","WORKER","UNIT 1","VMC MACHINE SHOP","SENIOR OPERATOR","PRODUCTION","HYDRALIC","9597372305","","eswaria1355@gmail.com","481916717822","0","ATDPA5210A","","","0","147001000430561","SSLC","",""],
  ["107","11001012","PALANI B","Male","married","1978-06-15","2007-01-05","WORKER","UNIT 1","CUTTING","SENIOR OPERATOR","PRODUCTION","COMMON","8056640604","","palanepalaneb@gmail.com","629920087210","0","HIJPP6900G","","","0","147001000541793","","",""],
  ["108","11001014","UMA S","Female","married","1980-01-26","2007-05-01","WORKER","UNIT 1","DEBURRING","HELPER","PRODUCTION","AUTOMOTIVE","8870049273","","hrd-unit1@microtechcnc.in","523085541829","0","","","","0","147001000532863","5th","",""],
  ["109","11001015","VANJULA R","Female","married","1976-03-06","2007-05-01","WORKER","UNIT 1","DEBURRING","HELPER","PRODUCTION","AEROSPACE","7667976476, 9600859181","","sunilkumar33222@gmail.com","454089931432","0","BSWPV8879B","","","0","147001000532011","","",""],
  ["110","11001016","KAMAKSHIYAMMA K","Female","married","1973-07-18","2007-05-01","WORKER","UNIT 1","DEBURRING","HELPER","PRODUCTION","AEROSPACE","9500536392, 9600859181","","hrd-unit1@microtechcnc.in","938745784770","0","ECIPK8829M","","","0","147001000532872","","",""],
  ["111","11001018","RAMADEVI S","Female","married","1968-04-05","2007-08-01","WORKER","UNIT 1","HOUSE CLENNING","HELPER","PRODUCTION","COMMON","9789178265","","hrd-unit1@microtechcnc.in","813448780612","0","DAPPR3803G","","","0","147001000531997","","",""],
  ["112","11001019","GOWRAMMA V","Female","married","1975-11-25","2007-08-06","WORKER","UNIT 1","DEBURRING","HELPER","PRODUCTION","AUTOMOTIVE","8144863941","","shruthiyadhav1@gmail.com","841643587930","0","","","","0","147001000532869","","",""],
  ["113","11001020","RATHNAMMA K","Female","married","1974-05-21","2007-09-01","WORKER","UNIT 1","CANTEEN","HEAD COOK","ADMIN STAFF","COMMON","9626784993","","hrd-unit1@microtechcnc.in","782661672977","0","EVVPK3315L","","","0","147001001169719","","",""],
  ["114","11001021","JANAKI M","Female","married","1975-04-07","2007-09-01","WORKER","UNIT 1","QUALITY","INSPECTOR","ADMIN STAFF","AUTOMOTIVE","9787228227","","hrd-unit1@microtechcnc.in","726147917636","0","BTBPJ5155Q","","","0","147001000974721","HSC","ARUL & CO, ESSAR TOOLS, MICRO TECH PRESSING PVT LTD","PRESS OPERATOR, PRESS OPERATOR, QUALITY INSPESTION"],
  ["115","11001023","VENKATESAN R","Male","married","1990-06-15","2007-09-10","WORKER","UNIT 1","VMC MACHINE SHOP","SENIOR OPERATOR","PRODUCTION","HYDRALIC","6383898925","","rvenkateshmicrotechcnc@gmail.com","752748472193","0","","","","0","147001000541787","SSLC","",""],
  ["116","11001024","SATHISH KUMAR R","Male","married","1988-04-07","2007-10-04","WORKER","UNIT 1","QUALITY","INSPECTOR","ADMIN STAFF","AUTOMOTIVE","7639422450","","sathishanu.chandru@gmail.com","876398078424","0","KKCPS4193G","","","0","147001000542050","SSLC","",""],
  ["117","11001034","VENKATESAN D","Male","married","1977-06-15","2010-02-09","WORKER","UNIT 1","VMC MACHINE SHOP","SENIOR OPERATOR","PRODUCTION","AUTOMOTIVE","9787935334","","hrd-unit1@microtechcnc.in","460154851934","0","BJUPV9865J","","","0","147001000852015","SSLC","",""],
  ["118","11001035","VENKATACHALAM M","Male","married","1971-03-15","2010-02-19","WORKER","UNIT 1","VMC MACHINE SHOP","SENIOR OPERATOR","PRODUCTION","HYDRALIC","9092158092","","venkatachalam15031971@gmail.com","493201258675","0","BNOPV9517M","","","0","147001000847906","ITI","SCIMTILLATING ENN CNC INDIA","CNC OPERATOR & Q.C CONTROL"],
  ["119","11001043","RAMESH BABU K","Male","married","1988-06-10","2011-03-11","WORKER","UNIT 1","DRIVER","DRIVER","PRODUCTION","COMMON","9442286109","","krameshbabu2009@gmail.com","515542919858","0","BRZPR3135G","TN24Z20060008255","","0","147001001153267","8 th","",""],
  ["120","11001045","KARTHIKEYAN N","Male","married","1987-06-15","2011-04-20","WORKER","UNIT 1","QUALITY","SENIOR INSPECTOR","ADMIN STAFF","AEROSPACE","9629026790","","n.koti93@gmail.com","575379723369","0","GPIPK0705K","TN7020130010576","","0","147001000849445","ITI MACHINIST","S.R ENGG , SELVAKUMAR MECHANICAL MANU, STAR KITCHEN EQUIPMENT","SUPERVISIOR, MECHANICAL SUPERVISIOR, FACTORY IN-CHARGE"],
  ["121","11001050","UMA R","Female","married","1974-03-29","2011-06-10","WORKER","UNIT 1","DEBURRING","HELPER","PRODUCTION","AEROSPACE","9952244091","","uma.uma6293174@gmail.com","824444833868","0","AHLPU9864A","","","0","147001001333064","SSLC","",""],
  ["122","11001051","VEERAPPA K S","Male","married","1971-05-05","2011-06-13","WORKER","UNIT 1","WASHING","SENIOR OPERATOR","PRODUCTION","COMMON","9488289910","","hrd-unit1@microtechcnc.in","513405099874","0","ASCPV3002F","","","0","147001001816995","BSC","",""],
  ["123","11001054","KARTHIK G","Male","married","1992-03-12","2011-11-02","WORKER","UNIT 1","CUTTING","SENIOR OPERATOR","PRODUCTION","COMMON","9688784190, 9994148045","","karthichandraleka@gmail.com","782098123377","0","GRAPK7842B","","","0","147001001711493","9 th","",""],
  ["124","11001055","KALIYAPPAN M","Male","married","1989-04-30","2011-11-26","WORKER","UNIT 1","VMC MACHINE SHOP","OPERATING ENGINEER","PRODUCTION","HYDRALIC","8122882739","","kaliyappan89mech@gmail.com","453679959753","0","CWYPK8885P","","","0","147001001817015","DME","",""],
  ["125","11001056","SAVATHRI T","Female","married","1984-10-08","2012-02-13","WORKER","UNIT 1","CANTEEN","COOK","ADMIN STAFF","COMMON","9787363154","","hrd-unit1@microtechcnc.in","826718640870","0","HKFPS4985E","","","0","147001001711496","8th Std","STAR DRAGS","PACKING"],
  ["126","11001057","MAHESWARAN P","Male","married","1988-06-04","2012-02-22","WORKER","UNIT 1","CNC AEROSPACE","OPERATING ENGINEER","PRODUCTION","AEROSPACE","9789630695","","msmahesh458@gmail.com","663335901564","0","GYXPM6162E","","","0","147001001711504","DECE","",""],
  ["127","11001066","RAVI KUMAR C","Male","married","1990-06-15","2013-01-23","WORKER","UNIT 1","CNC MACHINE SHOP","SENIOR OPERATOR","PRODUCTION","AUTOMOTIVE","9688655961","","ravinandhini322@gmail.com","895108821959","0","BZAPC5296E","","","0","147001001205034","HSC","SEQUEL LOGISTICS","STORE DEPARTMENT"],
  ["128","11001069","MUNI LAKSHMI G","Female","married","1975-08-07","2013-05-08","WORKER","UNIT 1","DEBURRING","HELPER","PRODUCTION","COMMON","9943376715","","divyagopallappa@gmail.com","955418629276","0","CFLPG2252J","","","0","147001001983728","9 th STD","",""],
  ["129","11001071","SARALA R","Female","married","1985-04-19","2013-05-30","WORKER","UNIT 1","WASHING","HELPER","PRODUCTION","COMMON","9486342193","","hrd-unit1@microtechcnc.in","509174562132","0","QCTPS2943P","","","0","147001001983734","8th Std","",""],
  ["130","11001072","MALARVIZHI N","Female","married","1979-05-30","2013-06-03","WORKER","UNIT 1","DEBURRING","HELPER","PRODUCTION","ELECTRIC VEHICLE","9944819767","","hrd-unit1@microtechcnc.in","434715656642","0","","","","0","147001001983732","HSC","",""],
  ["131","11001077","SATHYA L","Female","married","1992-05-21","2013-09-28","WORKER","UNIT 1","VMC MACHINE SHOP","OPERATOR","PRODUCTION","HYDRALIC","9842035914","","hrd-unit1@microtechcnc.in","538782983151","0","NROPS5992F","","","0","147001002199824","8 th Std","",""],
  ["132","11001093","DEVARAJAN N","Male","married","1989-05-13","2015-06-10","WORKER","UNIT 1","VMC MACHINE SHOP","SENIOR OPERATOR","PRODUCTION","HYDRALIC","9600825534","","ndevarajan1989@gmail.com","371570016830","0","BUNPD4743F","","","0","500101010676986","ITI FITTER","TVS MOTOR CO LTD, ALSTOM T & D INDIA ,TD","CNC OPERATOR, APPERENTICE"],
  ["133","11001094","THAMARAI SELVAN S","Male","single","1997-06-12","2015-06-11","WORKER","UNIT 1","QUALITY","ASSISTANT ENGINEER","ADMIN STAFF","ELECTRIC VEHICLE","9944187500","","thamaraikani002@gmail.com","507991731069","0","","","","0","500101010600167","DME","",""],
  ["134","11001099","KANNAN S","Male","single","1993-06-05","2015-06-22","WORKER","UNIT 1","CONVENTIONAL","SENIOR OPERATOR","PRODUCTION","ELECTRIC VEHICLE","9597427945","","kannavijay4@gmail.com","549327936805","0","DGKPK4898H","","","0","500101010600208","ITI","TVS MOTOR CO LTD, TVS MOTOR CO LTD","APPRENTICE, TEMPORARY WORKMAN"],
  ["135","11001120","RAJKUMAR C","Male","single","1995-06-10","2016-03-07","WORKER","UNIT 1","CNC MACHINE SHOP","SENIOR OPERATOR","PRODUCTION","HYDRALIC","9087434677","","rajkumarbarathi95@gmail.com","276369433541","0","","","","0","500101010826278","ITI","",""],
  ["136","11001170","DHANASEKAR M","Male","single","1995-07-07","2017-03-22","WORKER","UNIT 1","CONVENTIONAL","SENIOR OPERATOR","PRODUCTION","AUTOMOTIVE","7200226261","","dhanasekarandharasekaran421@gmail.com","200290574394","0","","","","0","500101011416747","HSC","KERSER NEROLEX PAINTS","HELPER"],
  ["137","11001229","JAYA T","Female","married","1988-01-01","2017-08-18","WORKER","UNIT 1","WASHING","HELPER","PRODUCTION","COMMON","9843145273","","hrd-unit1@microtechcnc.in","553243521336","0","BLHPJ4720K","","","0","500101011542263","7TH","",""],
  ["138","11001230","PAVITHRA L","Female","married","1987-01-11","2017-08-18","WORKER","UNIT 1","DEBURRING","HELPER","PRODUCTION","AUTOMOTIVE","9786117204","","hrd-unit1@microtechcnc.in","996580645190","0","DJSPP9022D","","","0","500101011542172","","",""],
  ["139","11001231","PARVADHI S","Female","married","1983-04-24","2017-08-19","WORKER","UNIT 1","DEBURRING","HELPER","PRODUCTION","AUTOMOTIVE","7868918275","","hrd-unit1@microtechcnc.in","957445530796","0","","","","0","500101011542173","8TH","",""],
  ["140","11001366","NAVEENKUMAR D","Male","single","1997-07-16","2018-03-07","WORKER","UNIT 1","CONVENTIONAL","JUNIOR OPERATING ENGINEER","PRODUCTION","ELECTRIC VEHICLE","9159105438","","naveenkumar5439@gmail.com","706736694283","0","","TN7020160004476","","0","500101011777697","DIPLOMA IN ME","",""],
  ["141","11001432","SAVITHA R","Female","married","1990-06-10","2018-05-25","WORKER","UNIT 1","VMC MACHINE SHOP","OPERATOR","PRODUCTION","HYDRALIC","7538886199","","savithars2018@gmail.com","535042329565","0","CPIPA0050Q","","","0","500101011867698","9TH","",""],
  ["142","11001444","PRAVEEN KUMAR R","Male","single","1995-03-10","2018-06-01","WORKER","UNIT 1","VMC MACHINE SHOP","OPERATING ENGINEER","PRODUCTION","HYDRALIC","8122988816, 8526060679","","praveenme338@gmail.com","727191338681","0","CDCPP2183E","","","0","500101011867809","B.TECH - ME","TRIVENI E=WIRE TECH","VMC MACHINE"],
  ["143","11001458","MUTHU K","Male","married","1989-04-11","2018-06-20","WORKER","UNIT 1","CONVENTIONAL","JUNIOR OPERATING ENGINEER","PRODUCTION","ELECTRIC VEHICLE","9500778301","","ecemuthuvel@yahoo.com","776263072255","0","CDKPM5024K","","","0","500101011867827","","",""],
  ["144","11001466","BALAJI R","Male","single","1998-05-09","2018-06-28","WORKER","UNIT 1","CNC AEROSPACE","JUNIOR OPERATING ENGINEER","PRODUCTION","ELECTRIC VEHICLE","7094316183","7094316183","rbalaji09051998@gmail.com","986691513219","0","","","","0","500101011945071","DECE","ACENT CIRCUITS PVT LTD","OPERATOR"],
  ["145","11001535","CHANDRAPAL M","Male","married","1987-06-27","2018-11-14","WORKER","UNIT 1","VMC MACHINE SHOP","OPERATING ENGINEER","PRODUCTION","HYDRALIC","9750270963","","chandrapal.c143@gmail.com","811425060511","0","DHWPM0120H","","","0","147001001279998","DME","SUNDARAM FASTENERS LTD","TECHINAL TRAINEE"],
  ["146","11001538","ESWARAN V","Male","single","1998-05-02","2018-11-19","WORKER","UNIT 1","CNC AEROSPACE","JUNIOR OPERATING ENGINEER","PRODUCTION","AUTOMOTIVE","9626591724","","eswaraneswaran2706@gmail.com","523682314399","0","","","","0","500101011964814","DECE","",""],
  ["147","11001559","UMA S","Female","married","1975-01-01","2019-03-12","WORKER","UNIT 1","CANTEEN","COOK","ADMIN STAFF","COMMON","9791819023","","hrd-unit1@microtechcnc.in","625506579797","0","ALPPU0990D","","","0","500101012127604","","",""],
  ["148","11001560","GEETHA S","Female","married","1983-11-20","2019-03-15","WORKER","UNIT 1","CANTEEN","COOK","ADMIN STAFF","COMMON","9790515819","","hrd-unit1@microtechcnc.in","455396907605","0","CVVTG9153Q","","","0","500101012127602","","",""],
  ["149","11001562","SIVAGAMI P","Female","married","1976-03-26","2019-03-11","WORKER","UNIT 1","HOUSE CLENNING","HOUSE KEEPING","PRODUCTION","COMMON","6374831764","","hrd-unit1@microtechcnc.in","975516369403","0","JWBPS0785J","","","0","500101012127603","8 th Std","",""],
  ["150","11001563","LAKSHMAMMA G","Female","married","1977-04-05","2019-04-03","WORKER","UNIT 1","HOUSE CLENNING","HOUSE KEEPING","PRODUCTION","COMMON","9655319618","","hrd-unit1@microtechcnc.in","779710194756","0","AKWPL1556E","","","0","500101012083751","5 Std","",""],
  ["151","11001589","HARIKUMAR K","Male","married","1990-06-24","2021-11-27","WORKER","UNIT 1","CNC MACHINE SHOP","OPERATOR","PRODUCTION","AUTOMOTIVE","9092455661","","harikumar24061990@gmail.com","404839437971","0","0","0","","0","147001001333062","HSC","NEW OPPORTUNITIES, KARITA SEATING SYSTEM LTD, SUNDARAM AUTO COMPONENTS LTD, TVS MOTOR CO, MICRO-TECH CNC PVT LTD","RELATIONSHIP OFFICER, CASUAL LABOUR, CASUAL LABOUR, TEMPORARY WORKMAN, CNC OPERATOR"],
  ["152","11100271","AKTAR HUSSAIN A","Male","single","1995-03-01","2024-11-14","WORKER","UNIT 1","CUTTING","OPERATOR","PRODUCTION","COMMON","9003042189","9003042189","","880809434341","0","ALBPH3951P","0","","0","500101014038706","","",""],
  ["153","11100278","SYED AHMED S","Male","single","1999-05-20","2024-12-18","WORKER","UNIT 1","QUALITY","TRAINEE","ADMIN STAFF","COMMON","8072971461","8072971461","AHMEDDME007@GMAIL.COM","683250777475","0","NGSPS0514N","0","","0","500101014038741","DIPLOMA MECHANICAL ENGINEERING","",""],
  ["154","11100377","DINESH KUMAR R","Male","single","2002-07-18","2026-06-01","WORKER","UNIT 1","VMC MACHINE SHOP","JUNIOR OPERATING ENGINEER","ADMIN STAFF","COMMON","","","","","0","0","0","","0","500101014644067","","",""],
  ["155","11100378","SATHYA M R","Male","single","1986-05-19","2026-06-01","WORKER","UNIT 1","CNC AEROSPACE","OPERATOR","ADMIN STAFF","COMMON","","","","782968310056","0","OFSPS9039Q","0","","0","500101014394009","","",""],
  ["156","11100380","JYOTIRMAYEE SWAIN","Female","single","2002-10-04","2026-06-05","WORKER","UNIT 1","QUALITY","TRAINEE","ADMIN STAFF","COMMON","","","","675487641234","0","0","0","","0","0","","",""],
  ["157","11100391","DEEPAK K","Male","single","2001-05-25","2026-06-10","WORKER","UNIT 1","QUALITY","TRAINEE","ADMIN STAFF","COMMON","8637426836","8637426836","deepakkdeepak243@gmail.com","765432145678","0","IDSPD3902H","0","","0","500101014644103","","",""],
  ["158","11100408","ARAVIND.R","Male","married","1999-05-16","2026-06-22","WORKER","UNIT 1","QUALITY","TRAINEE","ADMIN STAFF","COMMON","6381624297","6381624297","aravindumar6381@gmail.com","456781234098","0","CVWPA8718G","0","","0","500101014394050","BSC","",""],
  ["159","11100417","MURUGAMMAL S","Female","single","1995-04-15","2026-06-23","WORKER","UNIT 1","CONVENTIONAL","OPERATOR","ADMIN STAFF","COMMON","","","","765809876543","0","0","0","","0","500101014644049","","",""],
  ["160","11100419","THIMMARAJ S","Male","single","1982-02-15","2026-06-24","WORKER","UNIT 1","ADMINISTRATION","HOUSE KEEPING","ADMIN STAFF","COMMON","","","","789065432345","0","0","0","","0","500101014644059","","",""],
  ["161","11100420","SARMA N","Male","single","1997-05-02","2026-06-24","WORKER","UNIT 1","QUALITY","JUNIOR ENGINEER","ADMIN STAFF","COMMON","","","","","0","0","0","","0","0","","",""],
  ["162","11100423","KAVITHA N","Male","married","1992-05-10","2026-06-25","WORKER","UNIT 1","CONVENTIONAL","OPERATOR","ADMIN STAFF","COMMON","","","","","0","0","0","","0","500101014394156","","",""],
  ["163","11100424","DEEPA MUNIRAJ","Male","married","1990-09-13","2026-06-25","WORKER","UNIT 1","CONVENTIONAL","OPERATOR","ADMIN STAFF","COMMON","","","","","0","0","0","","0","500101014644102","","",""],
  ["164","11100428","MUKILAN KALAISELVAN","Male","single","1998-08-26","2026-07-04","WORKER","UNIT 1","DRIVER","DRIVER","ADMIN STAFF","COMMON","","","","236237237272","0","0","0","","0","500101014644104","","",""],
  ["165","11100430","HARIHARAN K B","Male","single","1996-09-09","2026-07-09","WORKER","UNIT 1","QUALITY","ENGINEER","ADMIN STAFF","COMMON","","","","536353725272","0","0","0","","0","0","","",""],
  ["166","11100434","SANTHOSH S","Male","single","2008-01-20","2026-07-20","WORKER","UNIT 1","CNC AEROSPACE","TRAINEE","ADMIN STAFF","COMMON","8248856014","8248856014","","","0","0","0","","0","0","DME","",""],
  ["167","11100435","HARISHKUMAR","Male","single","2002-09-03","2026-07-21","WORKER","UNIT 1","QUALITY","JUNIOR ENGINEER","ADMIN STAFF","COMMON","","","","","0","0","0","","0","500101014644099","","",""],
  ["168","11100452","MALA P","Female","married","1986-02-16","2026-08-20","WORKER","UNIT 1","CANTEEN","COOK","ADMIN STAFF","COMMON","","","","","0","0","0","","0","500101014644066","","",""],
  ["169","11100453","LAVANYA R","Female","married","2003-06-14","2026-08-19","WORKER","UNIT 1","CNC AEROSPACE","OPERATOR","ADMIN STAFF","COMMON","","","","","0","0","0","","0","0","","",""],
  ["170","11100454","PALLAVI G","Female","married","1996-02-06","2026-08-19","WORKER","UNIT 1","CNC AEROSPACE","OPERATOR","ADMIN STAFF","COMMON","","","","","0","0","0","","0","0","","",""],
  ["171","11100463","EZHILARASAN K","Male","single","1998-06-17","2026-10-06","WORKER","UNIT 1","QUALITY","JUNIOR ENGINEER","ADMIN STAFF","COMMON","6379492572","6379492572","kumarezhil11@gmail.com","828531819396","0","0","0","","0","500101013116122","","",""],
  ["172","11001282","VASANTHI V","Female","married","1985-05-06","2017-11-02","WORKER TRAINEE","UNIT 1","CANTEEN","HEAD COOK","ADMIN STAFF","COMMON","8124145357, 9698555992","","hrd-unit1@microtechcnc.in","331234283979","0","AJMPV5717A","","","0","500101011640763","SSLC","MAVATTA MAGAMAI","COMMUNITY PROFESSIONALS & EXECUTIVE MEMBER"],
  ["173","11001591","PRABU S","Male","single","2002-03-07","2021-12-01","WORKER TRAINEE","UNIT 1","VMC MACHINE SHOP","JUNIOR OPERATING ENGINEER","PRODUCTION","HYDRALIC","9790157425","","","574341425241","0","0","0","","0","500101012948568","DCE","",""],
  ["174","11001600","HARISH VENKATASAMY","Male","single","1998-01-13","2021-12-02","WORKER TRAINEE","UNIT 1","VMC MACHINE SHOP","JUNIOR OPERATING ENGINEER","PRODUCTION","AUTOMOTIVE","7502983672","","","777188174064","0","0","0","","0","500101012948563","DEEE","",""],
  ["175","11001621","JAYARAMAN KUMAR","Male","single","2001-03-21","2022-02-02","WORKER TRAINEE","UNIT 1","VMC MACHINE SHOP","JUNIOR OPERATING ENGINEER","PRODUCTION","ELECTRIC VEHICLE","9043336524","","jaikishoreb@gmail.com","614696672775","0","0","0","","0","500101012936058","","",""],
  ["176","11001622","SENTHAMIZHAN M","Male","single","1999-05-17","2022-02-12","WORKER TRAINEE","UNIT 1","CNC AEROSPACE","JUNIOR OPERATING ENGINEER","PRODUCTION","HYDRALIC","9047631177","","simla.s.s.134333@gmail.com","652331952122","0","0","0","","0","500101012431158","","",""],
  ["177","11001636","SANDEEP M","Male","single","1999-03-18","2022-03-19","WORKER TRAINEE","UNIT 1","CONVENTIONAL","OPERATOR","PRODUCTION","COMMON","9361399299","","sandeepmurugan99@gmail.com","657264126907","0","0","0","","0","500101013116068","","",""],
  ["178","11001645","GOPINATHAN","Male","single","2003-03-19","2022-04-11","WORKER TRAINEE","UNIT 1","VMC MACHINE SHOP","OPERATOR","PRODUCTION","HYDRALIC","8015779129","","","842406317598","0","0","0","","0","500101013047184","SSLC","",""],
  ["179","11001664","KAMALESH N","Male","single","1995-09-07","2022-06-03","WORKER TRAINEE","UNIT 1","CNC AEROSPACE","OPERATOR","PRODUCTION","ELECTRIC VEHICLE","9585229698","","kamaleshvignesh176@gmail.com","834181654150","0","0","0","","0","500101013185887","CHENNAI","HARITA SEATING SYSTEM, SUNDARAM CLYTON","ASSEMBLY, ASSEMBLY"],
  ["180","11001666","JAGADESH SAMRAJ","Male","single","1997-04-10","2022-06-08","WORKER TRAINEE","UNIT 1","CNC MACHINE SHOP","JUNIOR OPERATING ENGINEER","PRODUCTION","ELECTRIC VEHICLE","9087947336","9087947336","JAGADESHDHARSHAN@GMAIL.COM","992684224056","0","BJSPJO498R","0","","0","500101013185854","DME","GABRIEL INDIA LTD","OPERATOR"],
  ["181","11001682","NAVEENKUMAR V","Male","single","2004-09-09","2022-09-15","WORKER TRAINEE","UNIT 1","VMC MACHINE SHOP","JUNIOR OPERATING ENGINEER","PRODUCTION","AUTOMOTIVE","7695849913","","naveenkumarnalini0509@gmail.com","619389207434","0","0","0","","0","500101012640372","DME","FRESHER","FRESHER"],
  ["182","11100006","AJITHKUMAR M","Male","single","1996-09-23","2022-11-21","WORKER TRAINEE","UNIT 1","VMC MACHINE SHOP","JUNIOR OPERATING ENGINEER","PRODUCTION","AUTOMOTIVE","8870643836","","arunajith150@gmail.com","859249018222","0","0","0","","0","500101013202798","DEEE","",""],
  ["183","11100038","NETHIGIRI E","Male","married","1983-06-08","2023-06-01","WORKER TRAINEE","UNIT 1","VMC MACHINE SHOP","OPERATOR","PRODUCTION","HYDRALIC","9740900931","","","853886696604","0","ASVPN7513Q","0","","0","500101013371973","HSC, DCA","",""],
  ["184","11100055","LOGESH R","Male","single","2004-09-05","2023-07-17","WORKER TRAINEE","UNIT 1","QUALITY","JUNIOR ENGINEER","ADMIN STAFF","AUTOMOTIVE","8098398859","","rlogeshrlogesh27@gmail.com","761705081439","0","0","0","","0","500101013546872","DME","",""],
  ["185","11100062","PRABHAKAR L","Male","single","1994-06-01","2023-07-25","WORKER TRAINEE","UNIT 1","QUALITY","TRAINEE","ADMIN STAFF","HYDRALIC","9444730716","","","576812009986","0","0","0","","0","500101013546894","12th Std","",""],
  ["186","11100071","KUMARESAN S","Male","single","1997-03-12","2023-08-04","WORKER TRAINEE","UNIT 1","QUALITY","JUNIOR ENGINEER","ADMIN STAFF","AUTOMOTIVE","8148282046","","S1766678@GMAIL.COM","249384603461","0","GFFPK9068J","0","","0","500101013546870","DECE","",""],
  ["187","11100080","SAKTHIVEL G","Male","single","1997-11-01","2023-08-16","WORKER TRAINEE","UNIT 1","CNC AEROSPACE","TRAINEE","PRODUCTION","AUTOMOTIVE","","","","308742682353","0","0","0","","0","500101013546901","D.M.E","",""],
  ["188","11100082","SANGUBALAN T","Male","single","2002-05-08","2023-09-01","WORKER TRAINEE","UNIT 1","CONVENTIONAL","TRAINEE","PRODUCTION","AUTOMOTIVE","9047725768","","","811883309193","0","0","0","","0","500101013062658","D.M.E","",""],
  ["189","11100101","ANBARASU A","Male","single","1997-06-21","2023-09-20","WORKER TRAINEE","UNIT 1","CNC AEROSPACE","TRAINEE","PRODUCTION","AUTOMOTIVE","7395894155","7395894155","anbarasu897@gmail.com","771848907524","REQ0833921","DJTPA3706C","TN2520240001270","","0","500101013062664","D.M.E","VST TILLERS &TRACTORS, TVS MOTOR","TRAINEE, NEEM"],
  ["190","11100108","PRAKASH R","Male","single","2001-07-31","2023-09-22","WORKER TRAINEE","UNIT 1","QUALITY","TRAINEE","ADMIN STAFF","AUTOMOTIVE","6385564307","6385564307","PRAKASHRAJA352@GMAIL.COM","642015647722","0","FJKPP6337R","TN83M20210004085","","0","500101013062646","DEEE","TVS MOTOR","TRAINEE"],
  ["191","11100151","LIVIN N","Male","single","1999-06-09","2023-12-04","WORKER TRAINEE","UNIT 1","CUTTING","TRAINEE","PRODUCTION","AUTOMOTIVE","8072147822","8072147822","livinlivin013@gmail.com","308077327420","0","0","0","","0","500101013062556","D.M.E","",""],
  ["192","11100154","VASUDEVAN V","Male","single","2004-04-06","2023-12-05","WORKER TRAINEE","UNIT 1","VMC MACHINE SHOP","TRAINEE","PRODUCTION","HYDRALIC","8778344721","8778344721","vadivelvasudevan2004@gmail.com","777196599140","0","0","0","","0","500101013546898","D.M.E","",""],
  ["193","11100172","VENKATESAN M","Male","single","1996-04-03","2024-02-01","WORKER TRAINEE","UNIT 1","CONVENTIONAL","TRAINEE","PRODUCTION","AUTOMOTIVE","8220839577","8220839577","venkatesanvenkat528@gmail.com","715308704892","0","DJNPM8642B","0","","0","500101013062613","ITI","",""],
  ["194","11100173","TAMILSELVAN","Male","single","1997-06-15","2024-02-01","WORKER TRAINEE","UNIT 1","CNC AEROSPACE","TRAINEE","PRODUCTION","AEROSPACE","9965786160","","tamilselvandme111@gmail.com","945227005288","0","BPIPT7418H","0","","0","500101013062631","DME","",""],
  ["195","11100203","MADHIVANAN S","Male","single","1998-06-04","2024-06-22","WORKER TRAINEE","UNIT 1","STORES","TRAINEE","ADMIN STAFF","COMMON","8220126908","8220126908","madhiv970@gmail.com","759887195837","0","GSTPM7953M","0","","0","500101013867556","D.M.E","",""],
  ["196","11100209","DHILLARASAN R","Male","single","2002-07-21","2024-06-26","WORKER TRAINEE","UNIT 1","QUALITY","TRAINEE","ADMIN STAFF","COMMON","9159335147","9159335147","dhilld01@gmail.com","784609196595","0","GQBPD8166B","0","","0","500101013867563","HSC","",""],
  ["197","11100211","PERUMAL S","Male","single","2005-04-10","2024-07-05","WORKER TRAINEE","UNIT 1","CNC AEROSPACE","TRAINEE","PRODUCTION","AUTOMOTIVE","7339480916","7339480916","pp213320@gmail.com","778943777879","0","HWOPP0583E","0","","0","500101013867565","DCSE","",""],
  ["198","11100219","NAVEENKUMAR M","Male","single","2005-12-01","2024-07-17","WORKER TRAINEE","UNIT 1","CONVENTIONAL","TRAINEE","PRODUCTION","AUTOMOTIVE","8220902265","8220902265","naveenguru701@gmail.com","643776966090","0","DAVPN0282B","0","","0","500101013877724","12th Std","",""],
  ["199","11100284","SRIDHAR S","Male","single","2004-07-07","2025-02-18","WORKER TRAINEE","UNIT 1","QUALITY","TRAINEE","ADMIN STAFF","COMMON","6380426745","6380426745","sridharvijaya401@gmail.com","329660567402","0","RRRPS1073J","0","","0","500101014038863","DME","",""],
  ["200","11100301","GUNA G","Male","single","2007-04-15","2025-06-12","WORKER TRAINEE","UNIT 1","CNC AEROSPACE","TRAINEE","PRODUCTION","AUTOMOTIVE","6383553192","6383553192","gunagguna619@gmail.com","739207203779","0","0","0","","0","500101014209858","DME","",""],
  ["201","11100313","GOKULRAJ","Male","single","1995-09-05","2025-08-11","WORKER TRAINEE","UNIT 1","CNC MACHINE SHOP","TRAINEE","PRODUCTION","AUTOMOTIVE","7502411813","7502411813","gokul6557@gmail.com","598333293623","0","BILPG8262L","TN31 20150001387","","0","500101014312799","DME","ASHOK LEYLAND","TEMPORARY WORKMAN"],
  ["202","11100320","RAMAKRISHNA","Male","single","2006-03-01","2025-09-12","WORKER TRAINEE","UNIT 1","VMC MACHINE SHOP","TRAINEE","PRODUCTION","COMMON","8341460150","8341460150","rs6598219@gmail.com","994568890711","0","HDVPR6242A","0","","0","0","DME","",""],
  ["203","11100324","VENKATESAN S","Male","single","2005-06-03","2025-10-03","WORKER TRAINEE","UNIT 1","VMC MACHINE SHOP","TRAINEE","PRODUCTION","COMMON","6379714855","6379714855","svenkatesan03062005@gmail.com","235699502176","0","CTVPV8450M","0","","0","500101014509030","I T I","ASHOK LEYLAND, ASHOK LEYLAND","APPRENTICE, TEMPORARY WORKMAN"],
  ["204","11100374","ANAND KUMAR S","Male","single","2006-03-11","2026-05-14","WORKER TRAINEE","UNIT 1","CNC MACHINE SHOP","TRAINEE","ADMIN STAFF","COMMON","","","","222687533782","0","0","0","","0","500101014394094","","",""],
  ["205","11100386","MADESHWARAN G","Male","single","2007-02-03","2026-06-08","WORKER TRAINEE","UNIT 1","VMC MACHINE SHOP","TRAINEE","ADMIN STAFF","COMMON","","","","345676549876","0","0","0","","0","0","","",""],
  ["206","11100406","AKASH S","Male","single","2000-06-03","2026-06-13","WORKER TRAINEE","UNIT 1","QUALITY","JUNIOR OPERATING ENGINEER","ADMIN STAFF","COMMON","","","","","0","0","0","","0","0","","",""],
  ["207","11100433","RAGU K","Male","single","2008-07-30","2026-07-20","WORKER TRAINEE","UNIT 1","CNC AEROSPACE","TRAINEE","ADMIN STAFF","AEROSPACE","","","","","0","0","0","","0","0","","",""],
  ["208","11100450","SARASWATHI SURESH","Male","married","1986-01-17","2026-08-11","WORKER TRAINEE","UNIT 1","CONVENTIONAL","HELPER","ADMIN STAFF","AUTOMOTIVE","","","","766251366297","0","0","0","","0","0","","",""],
  ["209","11100460","TAMILARASU","Male","single","2007-07-28","2026-09-14","WORKER TRAINEE","UNIT 1","CNC AEROSPACE","OPERATOR","ADMIN STAFF","COMMON","7904679922","7904679922","ntamilarasu39@gmail.com","574738404257","0","0","0","","0","0","DME","",""],
  ["210","11100461","SEKAR","Male","single","1998-07-06","2026-09-17","WORKER TRAINEE","UNIT 1","QUALITY","FINAL INSPECTION","ADMIN STAFF","COMMON","6381341451","6381341451","chandrasekarr339@gmail.com","739070953097","0","NGZPS9452L","0","","0","0","DECE","JAYASHREE","FINAL INSPECTION"],
  ["211","11100465","HARIKUMAR","Male","single","2007-10-14","2026-10-14","WORKER TRAINEE","UNIT 1","CNC AEROSPACE","OPERATOR","ADMIN STAFF","COMMON","8072647800","8072647800","harikumar1407@gmail.com","323255987176","0","0","0","","0","0","10TH","",""],
  ["212","11100466","RAJARATHINAM D","Male","married","1998-05-13","2026-10-17","WORKER TRAINEE","UNIT 1","CNC AEROSPACE","OPERATOR","ADMIN STAFF","AUTOMOTIVE","9629191566","","rajarathinam504@gmail.com","940507122174","0","0","0","","0","500101013202796","","",""],
  ["213","11100469","ILAKHIYAA S","Female","single","2004-07-01","2026-11-02","WORKER TRAINEE","UNIT 1","QUALITY","TRAINEE","ADMIN STAFF","COMMON","9345885959","9345885959","ilakhis277@gmail.com","645277172931","0","APDP13843M","0","","0","0","B.TECH","",""],
  ["309","22002003","LAKSHMI NARAYANAN M","Male","married","1983-06-01","2006-06-09","STAFF","UNIT 2","STORES","SENIOR OFFICER","ADMIN STAFF","COMMON","8056957144","8056957144","jagan.lokesh123@gmail.com","838323831874","0","GBUPM1962C","TN7020130006372","","0","147001000430562","12","FIEM","EXECUTIVE"],
  ["310","22002005","ANANDHABABU K","Male","married","1993-06-10","2018-01-18","STAFF","UNIT 2","MANAFACTURING","SENIOR ENGINEER","ADMIN STAFF","LM","9750076835","9750076835","anandhababu.mech03@gmail.com","858710200735","0","BFWPA9846Q","TN7020220000094","","0","500101011777569","BE","NEW TECH ENGG","TECH"],
  ["311","22002007","KAMALAKANNAN S","Male","single","1992-12-11","2018-05-10","STAFF","UNIT 2","QUALITY","SENIOR ENGINEER","ADMIN STAFF","COMMON","8124689187","","kannankamal11121992@gmail.com","257145645388","0","FNVPK2148N","","","0","500101011640820","BE -MECH","EXPERT INDUSRIES PRIVATE LIMITED, TENNECO AUTOMOTIVE INDIA PRIVATE LIMITED","ENG, ENG"],
  ["312","22002010","ARULRAJ A","Male","single","1991-01-31","2018-09-17","STAFF","UNIT 2","QUALITY","SENIOR ENGINEER","ADMIN STAFF","TEREX","9789195042, 8667352612","","arularasusj@gmail.com","910362235506","0","","TN7020160006595","","0","500101012061354","DME","ESJAY ENGINEWERING WORKS","PRODUCTION PLAINING ENGINEERING"],
  ["313","22002011","SARAVANAN R","Male","married","1993-04-15","2019-02-01","STAFF","UNIT 2","MAINTENANCE","SENIOR ENGINEER","ADMIN STAFF","COMMON","9042327142","9042327142","saravananelectrical904@gmail.com","449613758418","TVC1009190","HEFPS0087M","TN7020240005804","","0","500101012127586","DIPLOMA, 10, 10TH","PRAVEEN ENGINEERING, RAJASHRIYA, ANANDA CNC","ENGINEER, TRAINEE, TRAINEE"],
  ["314","22003003","SAKTHIVEL R","Male","married","1978-04-04","2001-02-19","STAFF","UNIT 2","MANAFACTURING","SENIOR SUPERVISOR","ADMIN STAFF","LM","8148086059","8148086059","SATHIVEL20878@gmail.com","912401416890","0","CLLPS3063F","","","0","500101012958113","10TH","REVATHI FABRICATION","FITTER"],
  ["315","22003004","MADESH S","Male","married","1983-02-05","2005-03-14","STAFF","UNIT 2","MANAFACTURING","SENIOR SUPERVISOR","ADMIN STAFF","LM","9940861248","9940861248","madesh.sonnappa2015@gmail.com","341041379326","0","BVKPM7286E","TN7020110009455","","0","147001000542057","SSLC","AUTOMOTIVE AXLE , MRF TYRE, ASHOK LEYLAND","OPERATOR, OPERATOR, OPERATOR"],
  ["316","22003001","KAMARAJ S","Male","married","1975-04-04","1996-08-01","WORKER","UNIT 2","CUTTING","SENIOR OPERATOR","PRODUCTION","LM","9790603631","9790603631","kamarajk506@gmail.com","891027605972","0","JXPPS4753F","","","0","147001000519865","SSLC","",""],
  ["317","22003002","KANNIYAPPAN A","Male","married","1978-03-16","1996-08-01","WORKER","UNIT 2","ASSEMBLY","SENIOR OPERATOR","PRODUCTION","LM","9940729478","9940729478","kanniappankanni191@gmail.com","894322718864","0","DXTPK5936C","F/TN/24Z/006353/2005","","0","147001000494728","9TH","",""],
  ["318","22003010","GOVINDASAMY P","Male","married","1976-05-12","1993-06-20","WORKER","UNIT 2","DRIVER","SENIOR OPERATOR","PRODUCTION","COMMON","8300963217","8300963217","govindasamyp1205@gmail.com","256823435693","0","CBQPG3317M","TN24Z20060005962","","0","147001000510484","5th","",""],
  ["319","22003013","ARUNKUMAR R","Male","married","1974-04-14","2017-11-01","WORKER","UNIT 2","DRIVER","SENIOR OPERATOR","PRODUCTION","COMMON","9952453756","9952453756","arunkumarlokesh884@gmail.com","284137151077","0","ANXPA9654L","","","0","147001000517729","10TH","",""],
  ["320","22003021","VELU C","Male","married","1995-07-05","2021-01-27","WORKER","UNIT 2","BENDING","TECHNICIAN","PRODUCTION","TEREX","9620062013","9620062013","velucm125@gmail.com","501082925299","0","","","","0","500101012603269","ITI","RISHI LASER CO. PVT LTD","METAL FORMING AND FABRICATION"],
  ["321","22200008","DILIP","Male","married","1988-01-01","2024-09-02","WORKER","UNIT 2","WELDING","WELDER","PRODUCTION","LM","9171888013","9171888013","DILIPKARISHMA89@GMAIL.COM","611204001577","ZBC1414457","CFNPD7005J","0","","0","500101013986445","8TH","",""],
  ["322","22200021","GOPI PONNUSAMY","Male","married","1976-01-10","2026-07-01","WORKER","UNIT 2","BENDING","OPERATOR","ADMIN STAFF","COMMON","9597113553","9597113553","gopi1011976@gmail.com","644655567528","0","0","0","","0","","","",""],
  ["323","22200022","BIPUL KAMAR","Male","single","1990-02-19","2026-07-01","WORKER","UNIT 2","PRODUCTION","FITTER","ADMIN STAFF","TEREX","","","","390114334276","0","0","0","","0","500101014394135","","",""],
  ["324","22200023","LATHA S","Female","married","1983-05-08","2026-07-01","WORKER","UNIT 2","HOUSE CLENNING","HOUSE KEEPING","ADMIN STAFF","COMMON","","","","867389970588","0","0","0","","0","500101014394096","","",""],
  ["325","22200024","MARISELVAM M","Male","single","2003-02-15","2026-07-22","WORKER","UNIT 2","QUALITY","TRAINEE","ADMIN STAFF","COMMON","","","","723779795868","0","0","0","","0","0","","",""],
  ["326","22200026","RAJENDRAN GOPAL","Male","single","1979-08-23","2026-10-21","WORKER","UNIT 2","WELDING","WELDER","ADMIN STAFF","COMMON","9092731644","","","","0","0","0","","0","0","","",""],
  ["345","33004003","KRISHNA MOORTHY S","Male","married","1988-11-14","2010-04-25","STAFF","UNIT 3","PRODUCTION","SENIOR MANAGER","PRODUCTION","COMMON","9487041687, 9597008107","","moorthyk276@gmail.com","965753874474","0","CIJPK7985D","TN7020150003123","","0","147001000851555","ITI","",""],
  ["346","33004032","PUSHPARAJ S","Male","married","1986-04-25","2017-08-04","STAFF","UNIT 3","WELDING","ASSISTANT MANAGER","PRODUCTION","PRESS SHOP","9942221940","","PUSHPA15199@GMAIL.COM","751809283254","0","","TN11 20170004084","","0","500101011556141","","",""],
  ["347","33004038","DHAMOTHARAN N","Male","married","1980-04-25","2017-09-25","STAFF","UNIT 3","SUPPLY CHAIN MGMT","SENIOR ENGINEER","PRODUCTION","COMMON","8939479398","","kndhamu@gmail.com","974740084829","0","","E/TN/032/001449/2003","","0","500101011599487","","",""],
  ["348","33005029","KANDEEBAN K","Male","single","1994-06-06","2017-08-01","STAFF","UNIT 3","PRESS SHOP","ASSISTANT MANAGER","PRODUCTION","PRESS SHOP","95977845939","","kandeebank1994@gmail.com","668380828151","0","","","","0","500101011556134","","",""],
  ["349","33005072","LINGESHWARAN P","Male","single","1994-05-10","2018-04-24","STAFF","UNIT 3","TOOL ROOM","ASSISTANT ENGINEER","PRODUCTION","PRESS SHOP","9003503966","","lingeshwaran94.p@gmail.com","642935951037","0","","","","0","500101011880066","","",""],
  ["350","33005123","CHANDRU A","Male","single","1996-05-27","2018-10-05","STAFF","UNIT 3","VMC MACHINE SHOP","ASSISTANT MANAGER","PRODUCTION","COMMON","9789417726","","chandruanandanmech@gmail.com","352313552289","0","BACPC8872P","","","0","500101011949384","","",""],
  ["351","33005142","VINOTH V","Male","single","1996-05-13","2019-01-01","STAFF","UNIT 3","RD TANK","ASSISTANT MANAGER","PRODUCTION","HANNON","9047640443","","vinothmechvh@gmail.com","841737192917","0","BVOPV0058H","TN23T20150001254","","0","500101010991439","","",""],
  ["352","33005184","BABU T","Male","single","1996-05-06","2019-04-02","STAFF","UNIT 3","PROGRAM MANAGEMENT","ASSISTANT MANAGER","ADMIN STAFF","COMMON","7358665128","","babub4473@gmail.com","669432860379","0","","","","0","500101012155362","","",""],
  ["353","33005328","PRAKASH E","Male","single","1997-05-30","2020-09-15","STAFF","UNIT 3","STORES","ASSISTANT MANAGER","ADMIN STAFF","COMMON","7339600373","","prakash97e@gmail.com","773880048300","0","ELAPP0630J","","","0","500101012556077","BA","DAIMLER","PRODUCTION LINE"],
  ["354","33005350","MANIKANDAN E","Male","single","1995-05-08","2020-10-21","STAFF","UNIT 3","SUPPLY CHAIN MGMT","ASSISTANT MANAGER","PRODUCTION","PRESS SHOP","9940471796","","mano80053@gmail.com","781691776868","0","","","","0","500101012550878","BCOM","",""],
  ["355","33300012","PARTHIBAN M","Male","married","1987-03-21","2023-05-18","STAFF","UNIT 3","NPD","SUPERVISOR","ADMIN STAFF","COMMON","9940416123","9940416123","","223923486219","0","0","0","","0","500101013313849","SSLC","",""],
  ["356","33300013","KRISHNAN P","Male","single","1971-01-04","2023-06-01","STAFF","UNIT 3","OPERATIONS","GENERAL MANAGER","ADMIN STAFF","COMMON","9840953526","","KRISHNAN.PARAMASIVANPILLAI@GMAIL.COM","810720971553","0","ATTPK3610J","0","","0","500101013564388","DME","DYNAMIC TOOLING LTD, MICRO-TECH CNC PVT LTD, ADMACH AUTO INDIA LTD","OPEARTIONS HEAD, GENERAL MANAGER, GENERAL MANAGER"],
  ["357","33300014","ESAKI RAJA P","Male","single","1993-05-19","2023-06-05","STAFF","UNIT 3","CUTTING","SENIOR ENGINEER","PRODUCTION","COMMON","9159232363","9159232363","","331276892436","0","0","0","","0","500101011556107","DEEE, BE-EEE","",""],
  ["358","33300015","SANTHOSH V","Male","single","1998-05-20","2023-06-05","STAFF","UNIT 3","QUALITY","ENGINEER","ADMIN STAFF","PRESS SHOP","8778898360","8778898360","","617493329367","0","0","0","","0","500101013313869","BE-MECH","ALEX INDIA LTD, INDOCOOL LTD, JAMNA AUTO INDUSTRIES","PRODUCTION TRAINEE, ENGINEER, ENGINEER"],
  ["359","33300038","SAKTHIVEL S","Male","single","2000-04-08","2023-09-11","STAFF","UNIT 3","PPC","SENIOR EXECUTIVE","ADMIN STAFF","ELECTRIC VEHICLE","","","","581656100119","0","0","0","","0","500101012431744","BSC","",""],
  ["360","33300052","ARUNKUMAR M","Male","married","1991-06-14","2024-08-09","STAFF","UNIT 3","QUALITY","SENIOR ENGINEER","ADMIN STAFF","PRESS SHOP","8870148108","","m.arunmech91@gmail.com","435970867273","0","DEJPA9573J","0","","0","500101011556142","DIPLOMA IN MECHANICAL ENGINEER","FORD INDIA PVT LTD, HANON AUTOMOTIVE SYSTEMS INDIA LTD, MICRO TECH CNC PVT. LTD, WABCO INDIA LTD","COMPANY TRAINEE, GOVERNMENT APPRENTICE TRAINING, CMM INSPECTOR QA, QUALITY ENGINEER"],
  ["361","33300057","RAMAMOORTHY S","Male","single","1994-02-16","2025-04-02","STAFF","UNIT 3","NPD","SENIOR ENGINEER","ADMIN STAFF","COMMON","9791919626","9791919626","Rigopi1222@gmail.com","681269662685","0","0","0","","0","500101012366063","","",""],
  ["362","33300058","GOPINATH R","Male","single","1997-05-09","2025-04-01","STAFF","UNIT 3","NPD","ENGINEER","ADMIN STAFF","PRESS SHOP","","","","498264880218","0","0","0","","0","500101011880115","","",""],
  ["363","33300081","ANANDH","Male","single","1993-05-11","2025-12-11","STAFF","UNIT 3","QUALITY","SENIOR ENGINEER","ADMIN STAFF","COMMON","6383313501","6383313501","thalavanur2000@gmail.com","210457294718","0","0","0","","0","500101012698496","BE","MICROFIT INDUSTRIES, MICROFIT INDUSTRIES","ASST ENGINEER, TRAINEE"],
  ["364","33300082","DEEPAK DAYALAN","Male","single","2001-08-06","2025-12-22","STAFF","UNIT 3","MARKETING","EXECUTIVE","ADMIN STAFF","COMMON","6369543599","6369543599","deepak.dayalal@gmail.com","234798030746","0","GSYPD4520E","0","","0","500101012271077","BE","EXECUTIVE","EXECUTIVE-PC&L"],
  ["365","33300130","AYYAPPAN ANAND","Male","single","1997-11-06","2026-03-06","STAFF","UNIT 3","NPD","ASSISTANT MANAGER","ADMIN STAFF","COMMON","6380801502","6380801502","viratanand1819@gmail.com","306933319665","0","COKPA0735G","0","","0","0","DIPLOMA","SREE LAKSHMI PRECISION, MATCH MOVE AND ROTATION ARTIST","ASSISTANT MANAGER, ARTIST"],
  ["366","33300131","SATHIYAMOORTHY R","Male","married","1988-05-04","2026-03-10","STAFF","UNIT 3","NPD","ASSISTANT MANAGER","ADMIN STAFF","COMMON","9500478771","9500478771","VIJAYSATHYA@GMAIL.COM","485956039496","0","0","0","","0","500101011748512","DIPLOMA","GK ENGINEERING, RAJSRIYA AUTOMOTIVE","SENIOR ENGINEER, ASSISTANT MANAGER"],
  ["367","33300133","NAVEENKUMAR ASHOKKUMAR","Male","single","2000-09-09","2026-03-16","STAFF","UNIT 3","NPD","ENGINEER","ADMIN STAFF","COMMON","6382934479","6382934479","NAVEENKUMARA992000@GMAIL.COM,","845150342187","0","CIUPN9204R","0","","0","0","BE","RAJSRIYA AUTOMOTIVE","ASST MANAGER"],
  ["368","33300164","SAMPATH RAJ M","Male","married","1995-03-04","2026-04-06","STAFF","UNIT 3","SUPPLY CHAIN MGMT","ENGINEER","PRODUCTION","COMMON","8526141084","8526141084","mvsampath95@gmail.com","628424014239","0","0","0","","0","0","BE","KYOWA CASTEC INDUSTRIES, JBM AUTO, JBM AUTO","JUNIOR ENGINEER, TRAINEE, SUPERVISOR"],
  ["369","33300178","TEEKARAMAN D","Male","married","1983-06-20","2026-07-22","STAFF","UNIT 3","QUALITY","SENIOR MANAGER","ADMIN STAFF","COMMON","","","","","0","0","0","","0","0","","",""],
  ["370","33300180","GOPI","Male","single","1989-12-05","2026-07-31","STAFF","UNIT 3","MAINTENANCE","ASSISTANT MANAGER","ADMIN STAFF","COMMON","","","","","0","0","0","","0","0","","",""],
  ["371","33300189","VENKATESH","Male","single","2000-05-19","2026-09-04","STAFF","UNIT 3","QUALITY","ENGINEER","ADMIN STAFF","COMMON","8489460517","8489460517","","534270545323","0","0","0","","0","0","","",""],
  ["372","33300193","SELVAKUMAR S","Male","single","2001-06-01","2026-10-03","STAFF","UNIT 3","QUALITY","ASSISTANT ENGINEER","ADMIN STAFF","COMMON","9597060638","9597060638","","777779752227","0","0","0","","0","0","","",""],
  ["373","33300198","RAJ KUMAR UDHAYAKUMAR","Male","single","1990-06-12","2026-10-16","STAFF","UNIT 3","TOOL ROOM","MANAGER","ADMIN STAFF","COMMON","","","","735394904247","0","0","0","","0","0","","",""],
  ["374","33300199","SABAREESH BALAKRISHNAN","Male","married","1993-11-25","2026-10-19","STAFF","UNIT 3","HUMAN RESOURCE & ADMIN","DEPUTY MANAGER","ADMIN STAFF","COMMON","9952555337","9952555337","sabareeshbalakrishnan@outlook.com","849028070751","0","0","0","","0","0","","",""],
  ["375","33300046","TAMILZHAKAN BALAKRISHNAN","Male","single","2001-01-08","2024-03-25","STAFF TRAINEE","UNIT 3","MAINTENANCE","TECHNICIAN","ADMIN STAFF","COMMON","8754874651","8754874651","","228106455083","0","0","0","","0","500101012818989","ITI","",""],
  ["376","33300050","MOHAN RAJ K","Male","single","2001-10-14","2024-07-15","STAFF TRAINEE","UNIT 3","NPD","ENGINEER TRAINEE","ADMIN STAFF","COMMON","8754358425","","mraj87543@gmail.com","796691010537","0","GGHPM4895J","PY01 20210000497","","0","500101012593255","B.TECH MECHANICAL","PONDY KARNAVATI INDUSTRIAL PVT LTD","WORKER"],
  ["377","33005013","MANIKANDAN S","Male","single","1996-04-10","2016-05-01","WORKER","UNIT 3","RD TANK","JUNIOR ENGINEER","PRODUCTION","HANNON","8148546534","","MANIKANNAN063@GMAIL.COM","862606016297","0","","","","0","500101010821143","","",""],
  ["378","33005018","MURUGAN G","Male","single","1994-06-20","2016-05-01","WORKER","UNIT 3","RD TANK","JUNIOR ENGINEER","PRODUCTION","HANNON","9087574762","","gmgokul9387@gmail.com","381123551065","0","","","","0","500101010221569","","",""],
  ["379","33005140","ESWARAMOORTHY S","Male","single","1995-06-08","2019-01-01","WORKER","UNIT 3","RD TANK","ASSISTANT OPERATING ENGINEER","PRODUCTION","HANNON","9894479507","","eshwaresa.8695@gmail.com","529354649857","0","","","","0","500101010991465","","",""],
  ["380","33005146","SANTHAMOORTHI C","Male","single","1996-02-05","2019-01-01","WORKER","UNIT 3","PRESS SHOP","SENIOR OPERATOR","PRODUCTION","PRESS SHOP","9787554722","","moorthivijay671@gmail.com","299570959389","0","","","","0","500101011220730","","",""],
  ["381","33005147","KARUNAKARAN C","Male","single","1995-02-11","2019-01-01","WORKER","UNIT 3","QUALITY","ENGINEER","ADMIN STAFF","HANNON","8939274064","","karuna111995@gmail.com","970529436337","0","","","","0","500101011220612","","",""],
  ["382","33005161","SASIKUMAR M","Male","single","1996-11-08","2019-01-01","WORKER","UNIT 3","QUALITY","ENGINEER","ADMIN STAFF","PRESS SHOP","9840544889","","sasi081996@gmail.com","730423311660","0","","","","0","500101012155396","","",""],
  ["383","33005162","SURENDAR S","Male","single","1993-06-11","2019-01-01","WORKER","UNIT 3","QUALITY","ENGINEER","ADMIN STAFF","ELECTRIC VEHICLE","9943831019","","s.surendar123@gmail.com","","0","","","","0","500101011504162","","",""],
  ["384","33005229","AZHAGARSAMY B","Male","single","1993-05-10","2019-06-24","WORKER","UNIT 3","RD TANK","ASSISTANT OPERATING ENGINEER","PRODUCTION","ELECTRIC VEHICLE","9942502684","","azhagardece@gmail.com","778159971518","0","","","","0","500101012241025","","",""],
  ["385","33005324","DEEPAK S","Male","single","1994-05-06","2020-09-14","WORKER","UNIT 3","WELDING","ASSISTANT OPERATING ENGINEER","PRODUCTION","PRESS SHOP","8220662181","","msddeepak7@gmail.com","568123350270","0","","","","0","500101012555136","","",""],
  ["386","33005340","VENKATESH V","Male","single","2000-03-31","2020-10-01","WORKER","UNIT 3","RD TANK","TECHNICIAN","PRODUCTION","PRESS SHOP","9943516932","","vengatmahi90@gmail.com","517393243495","0","","","","0","500101012550809","","",""],
  ["387","33005361","HEMESH V","Male","single","2002-11-25","2021-04-21","WORKER","UNIT 3","VMC MACHINE SHOP","OPERATING ENGINEER","PRODUCTION","ELECTRIC VEHICLE","7094912016","","vhemesh04@gmail.com","481912794390","0","","","","0","500101012436638","","",""],
  ["388","33005362","SATHIARAJ","Male","single","1990-05-27","2021-07-01","WORKER","UNIT 3","STORES","ENGINEER","ADMIN STAFF","COMMON","9025682574","9025682574","sathyarajece2008@gmail.com","905663439149","0","KWBPS9357D","","","0","500101011599698","","",""],
  ["389","33300005","RAMACHANDRAN A","Male","single","1992-05-07","2023-03-24","WORKER","UNIT 3","PRESS SHOP","SENIOR OPERATOR","PRODUCTION","PRESS SHOP","9994726228","9994726228","","660076103961","0","0","0","","0","500101012030267","","",""],
  ["390","33300036","BALAGAN MICHAELSAMY J","Male","single","1997-12-26","2023-08-28","WORKER","UNIT 3","QUALITY","ASSISTANT ENGINEER","ADMIN STAFF","ELECTRIC VEHICLE","8344176584","","","870326069268","0","DIXPB7728C","0","","0","500101012593270","DEEE","SRI SIVASAKTHI AUTO ANCILLARIES, APPOLLO TYRES","FINAL INSPECTOR, SUPERVISOR"],
  ["391","33300065","SIVARAMAN S","Male","single","1975-05-10","2025-07-29","WORKER","UNIT 3","DRIVER","DRIVER","PRODUCTION","COMMON","","","","508476084203","0","0","0","","0","500101012593283","","",""],
  ["392","33300068","VIJAY T","Male","single","2000-01-03","2025-09-08","WORKER","UNIT 3","BENDING","JUNIOR OPERATING ENGINEER","PRODUCTION","COMMON","9361059772","9361059772","vijaythangaraj18307074@gmail.com","784760073361","0","CDOPV3324H","","","0","500101014321677","DIPLOMA","YAMAHA INDIA PVT LTD, NOKIA SOLUTIONS AND NETWORK","DIPLOMA APPRENTICE, DIPLOMA TRAINEE OPERATOR"],
  ["393","33300070","KALAIVANAN","Male","single","1997-06-03","2025-09-23","WORKER","UNIT 3","VMC MACHINE SHOP","JUNIOR OPERATING ENGINEER","PRODUCTION","PRESS SHOP","7094829440","7094829440","kalaikk7971@gmail.com","232284699634","0","IYGPK4569A","0","","0","500101014321656","DME","L.G. BALAKRISHNAN & BROS LIMITED, RAMCO CEMENTS, CRAFTS MAN","OPERATOR, APPRENTICE, TECHNICIAN"],
  ["394","33300071","PRADEEP MATHAVAN","Male","single","1997-07-02","2025-09-24","WORKER","UNIT 3","CUTTING","JUNIOR OPERATING ENGINEER","PRODUCTION","PRESS SHOP","9361780644","9361780644","pradeepprathi1997@gmail.com","923796818732","0","EYHPM7967P","TN82Z20200001686","","0","500101014321655","BE ECE","SCHNEIDER ELECTRIC, SAMRAJ ENG","TRAINEE, LASER OPERATOR"],
  ["395","33300076","VEERARAGHAVAN E","Male","married","1990-02-10","2025-11-06","WORKER","UNIT 3","CUTTING","JUNIOR OPERATING ENGINEER","PRODUCTION","COMMON","6381072673","6381072673","42051111431AME@GMAIL.COM","281038349971","0","AEMPE3037M","0","","0","0","BE","SHARADA MOTOR","TRAINEE"],
  ["396","33300079","VIJAY CHOKKALINGAM","Male","married","1992-02-02","2025-12-02","WORKER","UNIT 3","STORES","JUNIOR OPERATING ENGINEER","ADMIN STAFF","COMMON","","","","326289871541","0","0","0","","0","500101011880095","","",""],
  ["397","33300083","MOORTHY SHANMUGAM","Male","married","1994-04-06","2026-01-02","WORKER","UNIT 3","DRIVER","DRIVER","PRODUCTION","COMMON","9585162294","9585162294","MOORTHYSMS530@GMAIL.COM","638838481477","0","DKEPM7427Q","0","","0","500101014321671","ITI","TVS SUPPLY CHAIN SOLUITION","FORK LIFT DRIVER"],
  ["398","33300089","VIGNESH G","Male","single","1999-04-12","2026-02-09","WORKER","UNIT 3","CUTTING","JUNIOR ENGINEER","PRODUCTION","COMMON","8220873404","8220873404","VIGNESHGANESAN1999@GMAIL.COM","701607637114","0","0","0","","0","0","BE","HUNDAI MOBIS, RIKUN, POLY HOSE SATOSHOJI METAL WORKS","TRAINEE, NEEM TRAINEE, JUNIOR ENGINEER"],
  ["399","33300125","VIGNESH WARAN","Male","single","1998-07-13","2026-02-25","WORKER","UNIT 3","QUALITY","ENGINEER","ADMIN STAFF","COMMON","6379074123","6379074123","VIGNESH6860@GMAIL.COM","984553560485","0","0","0","","0","0","BE","KIKUWA INDIA, PRECISION PROFILE INDIA, JAMNA AUTO, MYOUNGSHIN INDIA","INSPECTOR, ENGINEER, TRAINEE, OPERATOR"],
  ["400","33300127","MANIKANDAN D","Male","single","2000-06-15","2026-03-02","WORKER","UNIT 3","QUALITY","JUNIOR ENGINEER","ADMIN STAFF","COMMON","","","","878648134058","0","HTOPD6786G","0","","0","0","BE","JAMNA AUTO INDUSTRIES, NEMAK","NEEM, APPRENTICE"],
  ["401","33300132","HEMANATH S","Male","single","2002-06-14","2026-03-11","WORKER","UNIT 3","TOOL ROOM","TECHNICIAN","PRODUCTION","COMMON","8825882636","8825882636","HEMANATHS1414@GMAIL.COM","734090276199","0","0","0","","0","500101014321716","DIPLOMA","RISHABA","ENGINEER"],
  ["402","33300134","RAJKUMAR M","Male","married","1990-05-03","2026-03-16","WORKER","UNIT 3","NPD","FITTER","ADMIN STAFF","COMMON","9585870145","9585870145","RAJKUMAR3590@GMAIL.COM","825114157954","0","0","0","","0","0","DIPLOMA","UGF","SUPERVISOR"],
  ["403","33300177","MUKSIDUL ISLAM","Male","single","2000-01-01","2026-07-13","WORKER","UNIT 3","BENDING","TRAINEE","ADMIN STAFF","COMMON","","","","","0","0","0","","0","0","","",""],
  ["404","33300184","SANTHAKUMAR NEELAKANDAN","Male","single","2005-05-05","2026-09-02","WORKER","UNIT 3","PRESS SHOP","TRAINEE","ADMIN STAFF","COMMON","","","","735485988786","0","0","0","","0","0","","",""],
  ["405","33300186","SATHISH MANI","Male","married","1985-12-07","2026-09-03","WORKER","UNIT 3","QUALITY","INSPECTOR","ADMIN STAFF","PRESS SHOP","","","","210039961442","0","0","0","","0","500101012821832","","",""],
  ["406","33300187","ASHOKKUMAR ELUMALAI","Male","single","1999-06-07","2026-09-04","WORKER","UNIT 3","QUALITY","JUNIOR ENGINEER","ADMIN STAFF","COMMON","9943728633","9943728633","ashok07061999@gmail.com","","0","0","0","","0","0","","",""],
  ["407","33300188","MARIMUTHU N","Male","single","1998-05-30","2026-09-04","WORKER","UNIT 3","QUALITY","TRAINEE","ADMIN STAFF","COMMON","9025420738","9025420738","marimuthu30598@gmail.com","","0","0","0","","0","0","","",""],
  ["408","33300191","DEEPAK SACHUTHANATHAM","Male","single","1998-06-09","2026-09-10","WORKER","UNIT 3","STORES","EXECUTIVE","ADMIN STAFF","COMMON","7448950410","7448950410","deepaksachu1998@gmail.com","767524960825","0","0","0","","0","0","MBA","",""],
  ["409","33300192","NANTHAKUMAR P","Male","single","2001-05-23","2026-09-22","WORKER","UNIT 3","PRODUCTION","JUNIOR OPERATING ENGINEER","ADMIN STAFF","COMMON","9790506692","9790506692","pnantha508@gmial.com","563748709603","0","0","0","","0","0","","",""],
  ["410","33300194","MOHAN KUMAR B","Male","single","2003-03-17","2026-10-07","WORKER","UNIT 3","QUALITY","ENGINEER","ADMIN STAFF","COMMON","","","","703851196320","0","0","0","","0","0","","",""],
  ["411","33300195","PREMKUMAR SURESHKUMAR","Male","single","2003-03-13","2026-10-10","WORKER","UNIT 3","PRODUCTION","OPERATOR","ADMIN STAFF","COMMON","","","","229703351200","0","0","0","","0","0","","",""],
  ["412","33300196","GIRISH S","Male","single","2002-12-07","2026-10-12","WORKER","UNIT 3","PRODUCTION","OPERATOR","ADMIN STAFF","COMMON","","","","880708468647","0","0","0","","0","0","","",""],
  ["413","33005077","THULASIDASS N","Male","single","1995-05-19","2018-05-03","WORKER TRAINEE","UNIT 3","VMC MACHINE SHOP","OPERATING ENGINEER","PRODUCTION","PRESS SHOP","9994661405","","thulasidassnt@gmail.com","734508224626","0","","","","BBBPT8302H","500101011880114","","",""],
  ["414","33005124","SUGUMAR V","Male","single","1993-07-27","2018-10-04","WORKER TRAINEE","UNIT 3","QUALITY","OPERATING ENGINEER","ADMIN STAFF","PRESS SHOP","8508021220","","sugumarv2793@gmail.com","434444387085","0","PGHPS3835K","","","0","500101011949449","","",""],
  ["415","33005135","JAYAKUMAR R","Male","married","1988-11-14","2018-10-22","WORKER TRAINEE","UNIT 3","QUALITY","OPERATING ENGINEER","ADMIN STAFF","PRESS SHOP","9944225835","","jayakumarprj@gmail.com","313441099633","0","","","","0","500101012028043","","",""],
  ["416","33005230","BALAJI V","Male","single","1996-07-23","2019-06-17","WORKER TRAINEE","UNIT 3","BENDING","SENIOR TECHNICIAN","PRODUCTION","PRESS SHOP","8270890096","","balajivadha237@gmail.com","894924177047","0","","","","0","500101011342551","","",""],
  ["417","33005232","MURUGAN R","Male","single","2000-01-19","2019-06-17","WORKER TRAINEE","UNIT 3","PRESS SHOP","SENIOR OPERATOR","PRODUCTION","PRESS SHOP","9597036177","","mmurugan9552@gmail.com","525432076521","0","","","","0","500101011599605","","",""],
  ["418","33005287","NANDHAKUMAR R","Male","single","1995-05-30","2020-08-04","WORKER TRAINEE","UNIT 3","QUALITY","ENGINEER","ADMIN STAFF","PRESS SHOP","9976855013","","nandhakumar199530@gmail.com","898696732137","0","","","","0","500101012436663","","",""],
  ["419","33005355","KAMALRAJ N","Male","single","1992-04-24","2020-12-07","WORKER TRAINEE","UNIT 3","DRIVER","DRIVER","PRODUCTION","COMMON","9176255925","","kamaljayasri88@gmail.com","818404288263","0","","","","0","500101012550894","","",""],
  ["420","33005360","IYAPPAN M","Male","single","1993-08-03","2021-04-21","WORKER TRAINEE","UNIT 3","RD TANK","OPERATING ENGINEER","PRODUCTION","PRESS SHOP","8220506230","8220506230","iyyappan.murugesan93@gmail.com","903217136323","0","","","","0","500101010991461","","",""],
  ["421","33005372","CHANDRU A","Male","single","1999-04-15","2022-02-22","WORKER TRAINEE","UNIT 3","PRESS SHOP","SENIOR OPERATOR","PRODUCTION","PRESS SHOP","8778002753","","","285617640692","0","0","0","","0","500101012910943","","",""],
  ["422","33300006","GOKUL K","Male","single","2003-06-23","2023-03-23","WORKER TRAINEE","UNIT 3","WELDING","TECHNICIAN","PRODUCTION","PRESS SHOP","","","","","0","0","0","","0","500101013313844","ITI","",""],
  ["423","33300017","MUGESH PRABU M","Male","single","2001-07-10","2023-06-06","WORKER TRAINEE","UNIT 3","QUALITY","INSPECTOR","ADMIN STAFF","ELECTRIC VEHICLE","9940715115","9940715115","","619335516983","0","0","0","","0","500101013313857","DIPLOMA, ITI","",""],
  ["424","33300022","PRAVEEN KUMAR J","Male","single","2000-04-06","2023-06-12","WORKER TRAINEE","UNIT 3","QUALITY","ASSISTANT ENGINEER","ADMIN STAFF","PRESS SHOP","9566953654","","PRAVEENKUMARSELVI49@GMAIL.COM","378737232951","0","0","0","","0","500101013313859","BE","SEIZO AUTOMOTIVE PVT LTD","ENGINEER"],
  ["425","33300028","RAGUL D","Male","single","2002-01-05","2023-08-08","WORKER TRAINEE","UNIT 3","QUALITY","INSPECTOR","ADMIN STAFF","PRESS SHOP","7558102602","7558102602","rascalragul101@gmail.com","994159301057","0","JAQPD2368D","0","","0","500101012431735","DIPLOMA, SSLC","MAGANA PVT LTD","FINAL INSPECTION"],
  ["426","33300029","AJITHKUMAR A","Male","single","2003-06-08","2023-08-11","WORKER TRAINEE","UNIT 3","QUALITY","INSPECTOR","ADMIN STAFF","ELECTRIC VEHICLE","9361736345","9361736345","ajithkumar6373@gmail.com","375805136110","0","ESHPA0996N","0","","0","500101012593335","DME","",""],
  ["427","33300033","VEERAMANI N","Male","single","2003-01-22","2023-08-25","WORKER TRAINEE","UNIT 3","QUALITY","INSPECTOR","ADMIN STAFF","ELECTRIC VEHICLE","9361084632","","","703378072873","0","CJRPV9068D","0","","0","500101012431737","DCE","",""],
  ["428","33300034","MADHANKUMAR M","Male","single","2003-01-02","2023-08-25","WORKER TRAINEE","UNIT 3","QUALITY","INSPECTOR","ADMIN STAFF","ELECTRIC VEHICLE","8489718631","","","503566789806","0","0","0","","0","500101012431736","DCE","",""],
  ["429","33300049","VIJAYAKUMAR E","Male","single","2002-08-31","2024-07-05","WORKER TRAINEE","UNIT 3","PRESS SHOP","TECHNICIAN","PRODUCTION","PRESS SHOP","8015800331","","vijayakumar.e198@gmail.com","751722997289","0","0","0","","0","500101013313848","ITI FITTER","MICRO TECH CNC PVT. LTD","WORKER TRAINEE"],
  ["430","33300055","VINOTHKUMAR R","Male","single","1993-03-07","2025-02-19","WORKER TRAINEE","UNIT 3","DRIVER","DRIVER","PRODUCTION","COMMON","9566595681","9566595681","","304739768734","0","0","TN2120120002365","","0","500101012593119","SSLC","ASIAN PAINTS PVT LTD","DRIVER"],
  ["431","33300063","MAHADEVAN","Male","single","2003-05-08","2025-07-01","WORKER TRAINEE","UNIT 3","RD TANK","TRAINEE","PRODUCTION","RD TANK","8807287691","8807287691","","445174740470","0","HIMPM064PQ","0","","0","500101014332425","","",""],
  ["432","33300064","KALAISELVAN G","Male","single","2003-12-17","2025-07-08","WORKER TRAINEE","UNIT 3","RD TANK","TRAINEE","PRODUCTION","RD TANK","8925237832","8925237832","","339715552269","0","0","0","","0","500101014321739","DME","",""],
  ["433","33300090","SETTU E","Male","married","1994-05-13","2026-02-10","WORKER TRAINEE","UNIT 3","DRIVER","DRIVER","PRODUCTION","COMMON","7639340027","7639340027","ANJAANSETTU07@GMAIL.COM","607682182779","0","HMFPS4257D","TN21 20150001366","","0","0","12th","GREEN TUFF","DRIVER"],
  ["434","33300128","LINGESHWARAN RAMU","Male","single","2002-06-12","2026-03-03","WORKER TRAINEE","UNIT 3","SUPPLY CHAIN MGMT","TRAINEE","PRODUCTION","COMMON","8778869597","8778869597","RAMULINGESWARAN@GMAIL.COM","264638411588","0","0","0","","0","0","BSC","",""],
  ["435","33300175","KALAIYARASAN S","Male","single","2003-03-10","2026-06-22","WORKER TRAINEE","UNIT 3","RD TANK","TRAINEE","ADMIN STAFF","COMMON","","","","354676549807","0","0","0","","0","0","","",""],
  ["436","33300176","RAMBABU U","Male","single","2002-06-24","2026-06-22","WORKER TRAINEE","UNIT 3","RD TANK","TRAINEE","ADMIN STAFF","COMMON","","","","908765431234","0","0","0","","0","0","","",""],
  ["519","11000007","VINOTH V","Male","married","1980-07-02","2004-02-01","STAFF","UNIT 4","OPERATIONS","ASSISTANT GENERAL MANAGER","ADMIN STAFF","COMMON","9487800111","","vinoth2kavi@gmail.com","939735204673","0","AHLPV3363P","","","0","147001000519867","","",""],
  ["520","11001028","DHILEEBAN M","Male","married","1989-05-30","2008-01-25","STAFF","UNIT 4","STORES","SENIOR OFFICER","ADMIN STAFF","COMMON","9500472403","","dhileepmicrotech@gmail.com","834610785503","0","CIMPD9822K","TN7020160010135","","0","147001000532361","HSC","",""],
  ["521","11001030","VADAMALAI C","Male","married","1982-07-29","2008-03-14","STAFF","UNIT 4","VMC MACHINE SHOP","SENIOR SUPERVISOR","PRODUCTION","AEROSTAR","9942316410","","devandevi771984@gmail.com","496311733952","0","APLPV8366A","","","0","147001000540909","ITI MACHINIST","TVS MOTOR COM, FAIVELEY TRANSPORT IND LTD, TVS MOTOR COM","APPRENTICE, MACHINE OPERATOR, CNC OPERATOR"],
  ["522","11001064","ANTHONY A","Male","married","1991-07-22","2012-05-23","STAFF","UNIT 4","ASSEMBLY","SENIOR ENGINEER","PRODUCTION","AEROSTAR","9626323979","","anthonysumi82@gmail.com","525679881849","0","DPQPA2607B","","","0","147001001711520","DME","",""],
  ["523","11001348","SIBBIPRASATH C","Male","single","1992-10-06","2018-02-12","STAFF","UNIT 4","VMC MACHINE SHOP","OPERATING ENGINEER","PRODUCTION","AEROSTAR","9688564289","","sihbabni@gmail.com","578182583793","0","","","","0","500101011587544","BE-MECH","TENNECO AUTOMOBILE INDIA PVT LTD, TVS SUNDARAM FASTENERS LTD","OPERATING ENGINEERING TRAINEE, OPERATING ENGG TRAINEE"],
  ["524","11001570","RAMU T S","Male","single","2001-06-30","2019-12-11","STAFF","UNIT 4","MAINTENANCE","ENGINEER","ADMIN STAFF","COMMON","99456580868144594944","","ramuananda13497789@gmail.com","377571531314","0","EKPPR1193Q","","","0","500101012353169","DIP, ITI (E& M)","SAMSUNG SHOEROOM","SYSTEMS WORK"],
  ["525","11001595","RAMAKRISHNAN SELVAM","Male","single","1991-02-15","2021-12-01","STAFF","UNIT 4","PRODUCTION","OPERATING ENGINEER","PRODUCTION","ELECTRIC VEHICLE","8940547851","","rama8940@gmail.com","286427192650","0","0","0","","0","500101012948576","DME","DIAMELER LTD, SUNGWOO HI-TECH IND LTD","PRODUCTION, QUALITY CONTROL"],
  ["526","11001647","PRAKASH R","Male","single","1999-05-10","2022-04-19","STAFF","UNIT 4","CUTTING PRODUCTION","ENGINEER","PRODUCTION","ELECTRIC VEHICLE","6379071116","","prakashr84880@gmail.com","855628558112","0","0","0","","0","500101013116070","BE","",""],
  ["527","11004039","SADEESH KUMAR M","Male","married","1985-06-19","2017-10-03","STAFF","UNIT 4","SUPPLY CHAIN MGMT","JUNIOR ENGINEER","PRODUCTION","ELECTRIC VEHICLE","9790155741","","sadeeshmoni@gmail.com","256610656859","0","FNSPS2368B","TN24Z20040001601","","0","500101011599486","SSLC, ITI MOLDING","",""],
  ["528","11100128","SASIKUMAR M","Male","single","1995-07-31","2023-10-16","STAFF","UNIT 4","QUALITY","ENGINEER","ADMIN STAFF","ELECTRIC VEHICLE","9715629187","","sasikumardm7@gmail.com","287607443630","0","EWSPM3010C","0","","0","500101013062721","B E","",""],
  ["529","11100131","JEGADEVA K","Male","single","1999-07-01","2023-10-25","STAFF","UNIT 4","QUALITY","JUNIOR ENGINEER","ADMIN STAFF","ELECTRIC VEHICLE","6380539996","","777srideva@gmail.com","802940651693","0","0","0","","0","500101013062698","ITL","",""],
  ["530","11100371","PRASANTH RAJENDRAN","Male","single","1994-07-21","2026-04-06","STAFF","UNIT 4","HUMAN RESOURCE & ADMIN","ASSISTANT MANAGER","ADMIN STAFF","COMMON","8675234700","8675234700","prasanthrp07@outlook.com","261421218184","0","COOPP5539P","TN30W20140002636","","0","500101014546920","","NATIONAL PLASTICS, AVALON COSMETICES , SM EXHAUST PVT LTD","HR & ADMIN , HR EXCE, SR HR EXEC"],
  ["531","22000003","RAJENDRAN M","Male","married","1972-05-20","1994-02-14","STAFF","UNIT 4","SUPPLY CHAIN MGMT","ASSISTANT ENGINEER","PRODUCTION","ELECTRIC VEHICLE","9487800108","","rajendhranraj78@gmail.com","921060392019","0","BFAPR4951P","","","0","147001000517721","9 th","",""],
  ["532","22002001","KULANDAI VEL A","Male","married","1969-01-15","1991-02-27","STAFF","UNIT 4","MANAFACTURING","SENIOR MANAGER","ADMIN STAFF","ELECTRIC VEHICLE","9487800114","","kulandai69@gmail.com","756170141866","0","BJAPK4104R","","","0","147001000517730","ITI","",""],
  ["533","22002002","KUMAR N","Male","married","1984-04-12","2009-08-14","STAFF","UNIT 4","QUALITY","DEPUTY MANAGER","ADMIN STAFF","ELECTRIC VEHICLE","9442293175","","kumar@microtechcnc.in","970583077041","0","CGZPK0500J","TN7020120005801","","0","147001000693033","DME","",""],
  ["534","33000025","PAZHANI T","Male","married","1979-06-05","2010-07-01","STAFF","UNIT 4","OPERATIONS","SENIOR MANAGER","ADMIN STAFF","ELECTRIC VEHICLE","94878001098667802624","","palani@microtechcnc.in","554786497469","0","AEOPT4954L","","","0","147001000847921","","",""],
  ["535","33005001","SAVARIAPPAN A","Male","married","1973-04-15","2007-09-01","STAFF","UNIT 4","NPD","ASSISTANT MANAGER","ADMIN STAFF","COMMON","9087254840","","lakshmisimon48382@gmail.com","210382245943","0","","","","0","147001000519868","12th","ESSAAR TOOLS PVT LTD","TOOL ROOM INCHARGE"],
  ["536","44400013","SURYA S","Male","single","2000-09-04","2024-04-11","STAFF","UNIT 4","WELDING","ENGINEER","PRODUCTION","COMMON","7092314200","7092314200","suryasaravanakumart@gmail.com","972793806832","0","KRGPS0032F","0","","0","500101013794971","BE, ECE","",""],
  ["537","44400041","VIDHYACHARAN K","Male","single","2000-09-19","2024-10-29","STAFF","UNIT 4","QUALITY","ENGINEER","ADMIN STAFF","AEROSTAR","8270223910","8270223910","","223514486400","0","BPIPV4428P","0","","0","500101014038751","B E","",""],
  ["538","44400074","ANJALI B","Female","single","2001-05-05","2024-12-16","STAFF","UNIT 4","QUALITY","DIPLOMA TRAINEE","ADMIN STAFF","AEROSTAR","6381896949","6381896949","anjalilux660@gmail.com","440339724037","0","CKYPA5963N","0","","0","500101014038912","BSC","TEAL, GLOBAL CALCIUM","SERVICE PROVIDER, QA DOCUMENTATION"],
  ["539","44400088","RAJESHKUMAR C","Male","married","1975-06-05","2025-03-26","STAFF","UNIT 4","PRODUCTION","MANAGER","PRODUCTION","ELECTRIC VEHICLE","9535160993","9535160993","rajeshwebb@gmail.com","715372421908","0","AKXPR4637F","0","","0","500101013062690","","",""],
  ["540","44400090","PUGAZHENTHI","Male","single","2002-01-09","2025-04-04","STAFF","UNIT 4","QUALITY","EXECUTIVE","ADMIN STAFF","COMMON","6374059070","6374059070","pugazhenthi796@gmail.com","839331285739","0","FROPP0983H","0","","0","500101014209894","DME","CIEL","TECHNICIAN"],
  ["541","44400145","SAKTHIVEL MARIYAPPAN","Male","single","1998-05-11","2025-08-04","STAFF","UNIT 4","PPC","JUNIOR ENGINEER","ADMIN STAFF","COMMON","9626983869","9626983869","msakthi016@gmail.com","589804258227","0","FCUPM8129R","TN83M20250000110","","0","500101014482158","BE","WINDCARE INDID PVT LTD, RENO JEL","TRAINEE, OPERATOR"],
  ["542","44400191","SATHISH RANGARAJ","Male","single","2003-06-24","2026-08-13","STAFF","UNIT 4","MAINTENANCE","JUNIOR ENGINEER","ADMIN STAFF","COMMON","","","","378641563496","0","HCAPR1490A","0","","0","0","","IHD INDUSTRIES PVT LTD","JUNIOR ENGINEER"],
  ["547","11001004","MURUGAN K","Male","married","1978-06-15","2003-01-18","WORKER","UNIT 4","ASSEMBLY","SENIOR OPERATOR","PRODUCTION","AEROSTAR","6383678022","","hrd-unit1@microtechcnc.in","530298218987","0","CYBPM3576Q","","","0","147001000477638","","",""],
  ["548","11001008","KUPENDRAN R","Male","married","1980-05-25","2004-04-14","WORKER","UNIT 4","QUALITY","ASSISTANT ENGINEER","ADMIN STAFF","ELECTRIC VEHICLE","9786432538","","","823108638022","0","","","","0","147001000494746","","",""],
  ["549","11001010","BALAJI B","Male","married","1985-04-03","2006-05-12","WORKER","UNIT 4","ASSEMBLY","SENIOR OPERATING ENGINEER","PRODUCTION","AEROSTAR","9944454222","","bvpranesh2013@gmail.com","280045660975","0","BIQPB4922B","TN2320090006788","","0","147001000540900","DECE","",""],
  ["550","11001025","ARUNKUMAR G N","Male","married","1989-05-18","2007-12-12","WORKER","UNIT 4","QUALITY","INSPECTOR","PRODUCTION","ELECTRIC VEHICLE","9751495834","","arunkumar66113@gmail.com","204792486111","0","BQLPA4466L","","","0","147001000540902","SSLC, ITI COURSE","",""],
  ["551","11001046","RAJAVEL M","Male","single","1990-08-26","2011-05-06","WORKER","UNIT 4","VMC MACHINE SHOP","ENGINEER","PRODUCTION","AEROSTAR","9788882867","","rajavelmech.vel@gmail.com","281177720695","0","","","","0","147001001131213","DME","",""],
  ["552","11001060","MICHAEL RAJ A","Male","married","1988-11-30","2012-03-13","WORKER","UNIT 4","CUTTING","SENIOR TECHNICIAN","PRODUCTION","ELECTRIC VEHICLE","9788417422","","michaelvictoria143@gmail.com","460689480732","0","EVSPA2751M","","","0","147001001711518","ITI TURNER","TVS MOTOR","TEMPORARY WORKER"],
  ["553","11001084","SATHISH A","Male","married","1989-12-21","2014-12-09","WORKER","UNIT 4","ASSEMBLY","OPERATOR","PRODUCTION","AEROSTAR","9486050501","","sathish19890007@gmail.com","809417799428","0","","TN24201900007504","","0","500101010563451","SSLC","RAME MADRAS LTD","ASSEMBLY"],
  ["554","11001171","KAMAL V","Male","single","1993-03-07","2017-03-22","WORKER","UNIT 4","STORES","JUNIOR OFFICER","ADMIN STAFF","ELECTRIC VEHICLE","9500472201","","vkamal7392@gmail.com","738418183111","0","FRBPK4746J","","","0","500101011416749","9TH","PRESS PRODUCTION PVT LTD","DRILLING & TAPPING SETTER"],
  ["555","11001545","AJITH C","Male","single","2000-01-10","2018-12-07","WORKER","UNIT 4","STORES","JUNIOR OFFICER","ADMIN STAFF","ELECTRIC VEHICLE","7402271013","","ajithkuriyanapalli@gmail.com","265158872104","0","CXKPA2783B","","","0","500101011977304","HSC","",""],
  ["556","11001588","VICHU M","Male","married","1994-06-05","2021-04-22","WORKER","UNIT 4","ASSEMBLY","OPERATOR","PRODUCTION","AEROSTAR","9514006971","9514006971","vichum1308@gmail.com","818786661403","0","BTLPV7891R","","","0","500101010826224","ITI FITTER","MICRO-TECH CNC PVT LTD, JOTHI MCHINE TOOLS, CUM MAK ENGG","CNC TURNING SHOP, CNC OPERATOR, FABRICATION WORKS"],
  ["557","22003006","SARAVANAN R","Male","married","1987-05-12","2010-12-01","WORKER","UNIT 4","WELDING","SENIOR OPERATING ENGINEER","PRODUCTION","AEROSTAR","8608992141","","saravananmonish100@gmail.com","273293324957","0","KUXPS5927R","","","0","147001000851200","","PRAVEEN ENGNINEERINGPVT LTD","EMPLOYEE"],
  ["558","44400049","VENKATESH K","Male","single","1999-05-16","2024-11-05","WORKER","UNIT 4","QUALITY","JUNIOR ENGINEER","ADMIN STAFF","COMMON","9626333765","9626333765","vv9743067@gmail.com","865019994375","0","LPEPK7229D","0","","0","500101013719459","DME","",""],
  ["559","44400059","PONNUSAMY SANGAPILLAI","Male","married","1994-06-02","2024-11-11","WORKER","UNIT 4","STORES","ENGINEER","ADMIN STAFF","COMMON","8838089171","8838089171","ponnarsathish94@gmail.com","920194095967","0","CSOPP4711K","0","","0","500101013719463","DME","ASHOL LEYLAND, SENTHUR TECH, OST","APPRENTICE, INCHARGE, QUALITY INSPECTOR"],
  ["560","44400073","GOPI KRISHNA GOPALAKRISHNAN","Male","single","1998-10-30","2024-12-09","WORKER","UNIT 4","ASSEMBLY - QUALITY","ASSISTANT ENGINEER","PRODUCTION","ELECTRIC VEHICLE","9943488477","9943488477","gopi6550@gmail.com","743488953155","0","CBZPG3994H","","","0","500101011415028","DME","RANE","TECHNICAL APPRENTICE"],
  ["561","44400075","RAJKUMAR SELLAPPAN","Male","single","1988-05-15","2024-12-20","WORKER","UNIT 4","QUALITY","JUNIOR ENGINEER","ADMIN STAFF","COMMON","9087525067","9087525067","rajkumarmicro88@gmail.com","407954717140","0","DNEPR3497A","0","","0","147001001169716","DME","",""],
  ["562","44400102","PRABAKARAN D","Male","single","1994-04-11","2025-07-07","WORKER","UNIT 4","ASSEMBLY","JUNIOR OPERATING ENGINEER","PRODUCTION","AEROSTAR","7667034537","7667034537","prabakaranvelu7@gmail.com","731774185947","0","BYZPP1800K","0","","0","500101014324348","D M E, DIPLOMA","GENAU EXTRUSIONS PVT. LTD., TVS MOTORS CO. LTD., FLEETGUARD FILTERS PVT. LTD., GABRIEL INDIA PVT. LTD., GENAU EXTRUSIONS PVT. LTD., GENAU EXTRUSIONS LTD.","OPERATION TRAINEE, APPRENTICE & TRAINEE, OPERATION TRAINEE, EMPLOYEE, OPERATIONS TRAINEE, TRAINEE"],
  ["563","44400117","BABU M","Male","single","2003-05-16","2025-07-15","WORKER","UNIT 4","ASSEMBLY","JUNIOR ENGINEER","PRODUCTION","AEROSTAR","6385402431","6385402431","babubabu007802@gmail.com","419288557818","0","GZXPM318IE","0","","0","0","DCSE","TVS","Q C"],
  ["564","44400118","NITHISHKUMAR D","Male","single","2006-06-17","2025-07-15","WORKER","UNIT 4","ASSEMBLY","TRAINEE","PRODUCTION","AEROSTAR","9789737950","9789737950","nithishkumar012007@gmail.com","430059346236","0","KIPPD0862L","0","","0","500101014323175","DME","",""],
  ["565","44400121","PANDIDURAI R","Male","single","1999-07-13","2025-07-16","WORKER","UNIT 4","ASSEMBLY","JUNIOR OPERATING ENGINEER","PRODUCTION","AEROSTAR","9025193432","9025193432","arunpandr1999@gmail.com","677584957856","0","DKJPR7082F","0","","0","500101014323202","DME","",""],
  ["566","44400122","SABARINATHAN M","Male","single","1998-06-09","2025-07-16","WORKER","UNIT 4","ASSEMBLY","JUNIOR OPERATING ENGINEER","PRODUCTION","AEROSTAR","9080382577","9080382577","sabarimurugan39@gmail.com","653941498270","0","KMMPS6641R","0","","0","500101014324321","DME","SUNDARAM - CLAYTON LTD, NEEDS","TECHNICIAN APPRENTICS, NEEDA MANPOWER"],
  ["567","44400125","SAMUEL DARLING D","Male","married","1995-10-14","2025-07-17","WORKER","UNIT 4","ASSEMBLY","JUNIOR OPERATING ENGINEER","PRODUCTION","AEROSTAR","9790549852","9790549852","joshuasamue1265@gmail.com","669154013377","0","IORPS9583F","0","","0","500101014324340","DME","",""],
  ["568","44400130","JAYAKUMAR S","Male","single","1998-10-01","2025-07-24","WORKER","UNIT 4","ASSEMBLY","ENGINEER TRAINEE","PRODUCTION","AEROSTAR","8248400962","8248400962","jayakumarselvam0110@gmail.com","890752106246","0","BNKPJ2649L","0","","0","500101014312835","BE","KNITWELL NEEDLES PVT LTD","DISPATCH"],
  ["569","44400132","HARIHARAN R","Male","single","2000-05-07","2025-07-24","WORKER","UNIT 4","ASSEMBLY","JUNIOR OPERATING ENGINEER","PRODUCTION","AEROSTAR","6379531916","6379531916","hariharan44649@gmail.com","378374318993","0","BHJPH8664J","0","","0","500101014498027","","TITAN, TITAN","NATS TRAINEE, NAPS TRAINEE"],
  ["570","44400134","SIVAMANI A","Male","single","1997-05-30","2025-07-24","WORKER","UNIT 4","ASSEMBLY","JUNIOR OPERATING ENGINEER","PRODUCTION","AEROSTAR","","","","437151991014","0","DBRPA0016H","0","","0","500101014312834","","",""],
  ["571","44400135","POOVARASAN A","Male","single","2000-05-25","2025-07-24","WORKER","UNIT 4","ASSEMBLY","JUNIOR OPERATING ENGINEER","ADMIN STAFF","AEROSTAR","7540023647","7540023647","poopoovarasan3454@gmail.com","431510938787","0","GRXPP9791M","0","","0","500101014312838","DIPLOMA","TVS MOTOR COMPANY","ON THE JOB TRAINNING"],
  ["572","44400141","SILAMBARASAN T","Male","single","1998-03-09","2025-07-24","WORKER","UNIT 4","QUALITY","JUNIOR OPERATING ENGINEER","ADMIN STAFF","AEROSTAR","","","","311631458487","0","IEOPS2418E","0","","0","500101014312829","","",""],
  ["573","44400146","JESU PRITHVI","Male","single","1999-01-20","2025-08-06","WORKER","UNIT 4","QUALITY","JUNIOR OPERATING ENGINEER","ADMIN STAFF","COMMON","8946088364","8946088364","jesuprithvi07@gmail.com","998032630035","0","0","0","","0","500101014312832","B.E","SWIFTANT, SHOBHAGLOBS ENGG","PROGRAMMER, JUNIOR ENGG"],
  ["574","44400174","PRABHAKAR V","Male","single","1999-06-15","2026-04-13","WORKER","UNIT 4","WELDING","WELDER","ADMIN STAFF","COMMON","9965821532","9965821532","","633672549585","0","0","0","","0","0","","ALF, VARSA","CONTRACT, CONTRACT"],
  ["575","44400177","K SARAVANAN","Male","married","1981-06-15","2026-05-09","WORKER","UNIT 4","PRODUCTION","WELDER","ADMIN STAFF","COMMON","8760253050","8760253050","","284785429072","0","0","0","","0","500101014394141","","",""],
  ["576","44400178","RAMESH ANNADURAI","Male","married","1982-06-04","2026-05-09","WORKER","UNIT 4","PRODUCTION","WELDER","ADMIN STAFF","COMMON","7200472038","7200472038","","381473257263","0","0","0","","0","500101014394087","","",""],
  ["577","44400179","VELU K","Male","married","1979-05-29","2026-05-09","WORKER","UNIT 4","PRODUCTION","WELDER","ADMIN STAFF","COMMON","9750069309","9750069309","","449221114448","0","0","0","","0","500101014394097","","",""],
  ["578","44400189","SASI KUMAR T","Male","single","2004-07-20","2026-08-01","WORKER","UNIT 4","VMC MACHINE SHOP","JUNIOR ENGINEER","ADMIN STAFF","COMMON","7338982030","9360256358","sasikumartsk03@gmail.com","460755871084","0","0","0","","0","0","","",""],
  ["579","44400193","ARAVINDHAN M","Male","single","2002-11-09","2026-08-20","WORKER","UNIT 4","QUALITY","TRAINEE","ADMIN STAFF","COMMON","9629322870","","","816423386924","0","0","0","","0","0","","",""],
  ["580","44400196","MUNIYAPPAN G","Male","single","1998-04-04","2026-09-22","WORKER","UNIT 4","QUALITY","JUNIOR ENGINEER","ADMIN STAFF","COMMON","","","","","0","0","0","","0","0","","",""],
  ["581","44400197","SABARIGANESAN G","Male","single","1999-05-05","2026-09-22","WORKER","UNIT 4","QUALITY","ENGINEER","ADMIN STAFF","COMMON","","","","","0","0","0","","0","0","","",""],
  ["582","11001680","BALAKRISHNAN M","Male","single","1999-11-05","2022-09-13","WORKER TRAINEE","UNIT 4","PRODUCTION","JUNIOR OPERATING ENGINEER","PRODUCTION","ELECTRIC VEHICLE","7449191860","","mbalakrishnan5111999@gmail.com","871515791595","0","0","0","","0","500101013202842","DME","TITAN ENGG AUTOMATION","OPERATOR"],
  ["583","11100013","DEENA DHAYALAN S","Male","single","2003-05-10","2022-12-02","WORKER TRAINEE","UNIT 4","WELDING","JUNIOR OPERATING ENGINEER","PRODUCTION","ELECTRIC VEHICLE","9092574015","","deenaselvaspbd@gmail.com","561213352426","0","OQVPS9392Q","0","","0","500101012640360","DME","LUCAS TVS P LTD LTD","FARMER"],
  ["584","11100067","GOKULNATH V","Male","single","2004-05-20","2023-08-01","WORKER TRAINEE","UNIT 4","ASSEMBLY","DIPLOMA TRAINEE","PRODUCTION","AEROSTAR","8056324732","","gokulnath805632@gmail.com","851281405844","0","0","0","","0","500101013546935","DME","",""],
  ["585","11100143","SENTAMILVANAN P","Male","single","2003-10-13","2023-11-23","WORKER TRAINEE","UNIT 4","ASSEMBLY","DIPLOMA TRAINEE","PRODUCTION","HYDRALIC","6379296902","6379296902","senthamilp@gmail.com","327300818509","0","0","0","","0","500101013062551","DME","",""],
  ["586","11100167","THANGAPRAKASH S","Male","single","2003-01-03","2024-01-18","WORKER TRAINEE","UNIT 4","ASSEMBLY","TRAINEE","ADMIN STAFF","AEROSTAR","9344028644","9344028644","thangaprakash676@gmail.com","378575810631","0","CHAPT4688N","0","","0","500101013062637","D.M.E","",""],
  ["587","11100174","RAJESH A","Male","single","1995-07-22","2024-02-05","WORKER TRAINEE","UNIT 4","ASSEMBLY","TRAINEE","PRODUCTION","AEROSTAR","8940047049","8940047049","rajeshrajesh10000@gmail.com","611460842725","0","EKRPR7304R","0","","0","500101013062633","DEEE","ASCENT CIRCUITS, SH ELECTRONICS","TRAINEE, TRAINEE"],
  ["588","11100177","SURESH V","Male","single","2000-06-30","2024-02-12","WORKER TRAINEE","UNIT 4","ASSEMBLY","TRAINEE","PRODUCTION","ELECTRIC VEHICLE","9384428899","9384428899","sureshk08083769","419878879388","0","BUAOV3935N","0","","0","500101013062634","12th","",""],
  ["589","11100196","PRAVEENKUMAR S","Male","single","1999-02-04","2024-06-06","WORKER TRAINEE","UNIT 4","ASSEMBLY","TRAINEE","PRODUCTION","HYDRALIC","6374517113","6374517113","mipraveenkumar6374@gmail.com","606019759203","0","FFWPP9937R","TN2920190004137","","0","500101013867561","DAE","",""],
  ["590","11100213","HARIHARAN K S","Male","single","1999-10-03","2024-07-09","WORKER TRAINEE","UNIT 4","ASSEMBLY","DIPLOMA TRAINEE","PRODUCTION","AEROSTAR","6383214274","6383214274","naveenss004@gmail.com","566515557453","0","BHNPH1562B","0","","0","500101013867560","DEEE","",""],
  ["591","11100253","SRIDHAR GANESAN","Male","single","2000-11-08","2024-10-16","WORKER TRAINEE","UNIT 4","QUALITY","ENGINEER","ADMIN STAFF","ELECTRIC VEHICLE","6382137144","6382137144","gsridhar811@gmail.com","910619934081","0","NZMPS5830L","0","","0","500101013719449","BE","",""],
  ["592","11100269","PASUPATHI K","Male","single","2002-06-02","2024-11-14","WORKER TRAINEE","UNIT 4","ASSEMBLY","TRAINEE","PRODUCTION","COMMON","9344378424","9344378424","pathpasu210@gamli.com","673999747146","ZHT1841105","0","0","","0","500101014038713","DIPLOMA","",""],
  ["593","11100346","JANARTHANAN R","Male","single","1998-06-18","2025-12-24","WORKER TRAINEE","UNIT 4","CNC MACHINE SHOP","TRAINEE","PRODUCTION","AUTOMOTIVE","9629877133","9629877133","janana333@icolud.com","882729953303","0","0","0","","0","500101014533379","KANCHANA R","",""],
  ["594","44400002","KADALARASAN M","Male","single","2001-11-26","2023-11-14","WORKER TRAINEE","UNIT 4","WELDING - SPM","DIPLOMA TRAINEE","PRODUCTION","COMMON","6383026110","6383026110","kadalarasannmk@gmail.com","449792452125","0","0","0","","0","500101013062699","","",""],
  ["595","44400007","AKILAN GOVINDARAJ","Male","single","2004-05-18","2024-02-20","WORKER TRAINEE","UNIT 4","CUTTING - SPM","DIPLOMA TRAINEE","PRODUCTION","ELECTRIC VEHICLE","6374363240","9698960274","gakilan55@gmail.com","247454692108","0","EJEPG8247Q","0","","0","500101013062640","DME","",""],
  ["596","44400021","VIJAY S","Male","single","2003-05-10","2024-05-14","WORKER TRAINEE","UNIT 4","QUALITY","DIPLOMA TRAINEE","PRODUCTION","ELECTRIC VEHICLE","7603828303","7603828303","vijay2003417@gmail.com","855619470155","0","BRWPV5289A","0","","0","500101013867521","DEEE, BE","",""],
  ["597","44400027","PRAKALATHAN S M","Male","single","2004-05-19","2024-09-02","WORKER TRAINEE","UNIT 4","QUALITY","INSPECTOR","ADMIN STAFF","AEROSTAR","8838693704","8838693704","prakalathansaravanan@gmail.com","496023554721","0","JJEPM9651K","0","","0","500101013986454","B.COM","",""],
  ["598","44400029","VIJAY A","Male","single","1997-06-20","2024-09-11","WORKER TRAINEE","UNIT 4","ASSEMBLY","DIPLOMA TRAINEE","PRODUCTION","ELECTRIC VEHICLE","9597295589","9597295589","vijivi231@gmail.com","446177261263","0","DSFPA3733L","0","","0","500101013986451","DEEE","",""],
  ["599","44400031","NAVAS B","Male","single","1999-04-09","2024-09-11","WORKER TRAINEE","UNIT 4","ASSEMBLY","DIPLOMA TRAINEE","PRODUCTION","ELECTRIC VEHICLE","9952681940","9952681940","navasnavas9357@gmail.com","616340376340","0","BYBPN0268B","0","","0","500101013986447","EEE","ASHOK LEYLAND","OPERATOR"],
  ["600","44400035","TAMIZHAN S","Male","single","2002-07-12","2024-09-23","WORKER TRAINEE","UNIT 4","ASSEMBLY","DIPLOMA TRAINEE","PRODUCTION","ELECTRIC VEHICLE","8838154313","8838154313","tamil18238660@gmail.com","576160552230","0","SJFPS2518H","0","","0","500101013719448","DME","",""],
  ["601","44400038","ABIMANI S","Male","single","2001-09-22","2024-10-01","WORKER TRAINEE","UNIT 4","ASSEMBLY","DIPLOMA TRAINEE","PRODUCTION","ELECTRIC VEHICLE","8680077693","8680077693","abomaniabimani228@gmail.com","219000978230","0","DZIPA0518M","0","","0","500101014042198","EEE","",""],
  ["602","44400053","SATHISHKUMAR S","Male","single","1996-06-07","2024-11-06","WORKER TRAINEE","UNIT 4","ASSEMBLY","DIPLOMA TRAINEE","PRODUCTION","ELECTRIC VEHICLE","9655578452","9655578452","sk1278566@gmail.com","400957468699","0","MS19S5512B","0","","0","500101014038714","DME","HARITA FEHRER LTD, MOBIS","TEMPORARY WORKMAN, ASSOCIATE TRAINEE"],
  ["603","44400054","SRIDHAR G","Male","single","2005-01-15","2024-11-06","WORKER TRAINEE","UNIT 4","ASSEMBLY","DIPLOMA TRAINEE","PRODUCTION","ELECTRIC VEHICLE","9655578452","9655578452","gsrithar036@gmail.com","962769609192","0","SLFPS2002N","0","","0","500101014038715","DME","ASHOK LEYLAND","ASSEMBLY"],
  ["604","44400061","SATHEESHKUMAR G","Male","married","1995-03-01","2024-11-11","WORKER TRAINEE","UNIT 4","WELDING","DIPLOMA TRAINEE","PRODUCTION","ELECTRIC VEHICLE","8344748488","8344748488","satheeshkumar1395@gmail.com","967757889561","0","EYVPS1797D","TN83Z20190004100","","0","500101014038707","","ASHOK LEYLAND UNIT 2, TOYOTA BOSHOKU AUTOMOTIVE INIDA PVY LTD","CAB WELD , MIG WELD"],
  ["605","44400070","KIRAN G","Male","single","2003-07-15","2024-11-26","WORKER TRAINEE","UNIT 4","VMC MACHINE SHOP","DIPLOMA TRAINEE","PRODUCTION","ELECTRIC VEHICLE","6374143452","6374143452","kiranmmit@gmail.com","575809541082","0","EAMPG1757C","0","","0","500101013062638","DME","",""],
  ["606","44400078","MOHANRAJ BABU","Male","single","2002-03-27","2025-03-10","WORKER TRAINEE","UNIT 4","QUALITY","TRAINEE","ADMIN STAFF","COMMON","6381770059","6381770059","bmohanraj845@gmail.com","825550223029","0","GRPPM4797G","0","","0","500101014038878","DME","TENNECO","GRADUATE APPRENTICE"],
  ["607","44400087","VIMAL KUMAR M","Male","single","2000-04-14","2025-03-20","WORKER TRAINEE","UNIT 4","ASSEMBLY","TRAINEE","PRODUCTION","ELECTRIC VEHICLE","9150696404","9150696404","vimalkutty1331@gmail.com","249015591283","0","GOMPM9772M","0","","0","500101014209893","DME","",""],
  ["608","44400092","PRAVEENKUMAR B","Male","married","2001-05-05","2025-06-11","WORKER TRAINEE","UNIT 4","WELDING","WELDER","PRODUCTION","ELECTRONICS","7806888201","7806888201","pk0643803467@gmail.com","356347600627","0","0","0","","0","500101014209929","DME","TOYOTA BOSHOKU, ASHOK LEYLAND, ASHOK LEYLAND","NEEM TRAINEE, TEMPORARY WORKMEN, APPRENTICE"],
  ["609","44400100","ADITHYA T","Male","single","2004-06-28","2025-06-23","WORKER TRAINEE","UNIT 4","QUALITY","TRAINEE","ADMIN STAFF","COMMON","7010558672","7010558672","adithyaadithya3208@gmail.com","720082108974","0","FSVPA8150D","0","","0","500101014313041","B.E","",""],
  ["610","44400110","KAVIYARASAN VENKATAJALAM","Male","single","2003-07-27","2025-07-09","WORKER TRAINEE","UNIT 4","ASSEMBLY","TRAINEE","PRODUCTION","ELECTRIC VEHICLE","9626193402","9626193402","kaviv587@gmail.com","650348167513","0","FBFPK4470K","0","","0","500101014324324","D M E","HYUNDAI MOBIS","PRODUCTION"],
  ["611","44400114","LAKSHMANAN P","Male","single","2003-10-11","2025-07-10","WORKER TRAINEE","UNIT 4","QUALITY","TRAINEE","ADMIN STAFF","COMMON","7806922611","9698583826","llakshusaran@gmail.com","222096642486","0","BVDPL9959G","0","","0","500101014324350","BE","",""],
  ["612","44400128","SHARAN V","Male","single","2002-02-28","2025-07-24","WORKER TRAINEE","UNIT 4","ASSEMBLY","TRAINEE","PRODUCTION","AEROSTAR","6369015176","6369015176","sharancrazy762@gmail.com","844265146640","0","CFWPV5908R","0","","0","500101014312830","B.COM","",""],
  ["613","44400129","RAJESH S","Male","single","2007-02-08","2025-07-24","WORKER TRAINEE","UNIT 4","ASSEMBLY","TRAINEE","PRODUCTION","AEROSTAR","9629119941","9629119941","mrsrajash08@gmail.com","949901114141","0","0","0","","0","500101014529113","DME","",""],
  ["614","44400137","LOKESH M","Male","single","1998-04-05","2025-07-24","WORKER TRAINEE","UNIT 4","ASSEMBLY","ENGINEER TRAINEE","PRODUCTION","AEROSTAR","9361107223","9361107223","logesh11064@gmail.com","763914627174","0","IGIPM5197N","0","","0","500101014312837","B.E (Mech)","",""],
  ["615","44400139","KARTHICH K","Male","single","1998-06-29","2025-07-24","WORKER TRAINEE","UNIT 4","ASSEMBLY","JUNIOR OPERATING ENGINEER","PRODUCTION","AEROSTAR","6374531239","6374531239","c.karthiksugan1998@gmail.com","401548130503","0","LWJPK7263F","0","","0","500101014498265","DME","ASHOK LEYLAND, ASHOK LEYLAND","TEMPORARY WORKMEN, APPRENTICE"],
  ["616","44400140","AJITHKUMAR MANI","Male","single","1998-05-16","2025-07-24","WORKER TRAINEE","UNIT 4","ASSEMBLY","JUNIOR OPERATING ENGINEER","PRODUCTION","AEROSTAR","9791452671","9791452671","ajthkmar012@gmail.com","216735313172","0","GQDPM2600B","0","","0","500101014498262","DME","GENIUS CONSULTANTS LTD","OPERATIONS ASSISTANT"],
  ["617","44400151","GOVINDHASAMI ERRAPPA","Male","single","1987-07-17","2025-09-10","WORKER TRAINEE","UNIT 4","PRODUCTION","QUALITY","PRODUCTION","COMMON","9566907119","9566907119","","727570401932","0","ACLPE4001A","0","","0","500101013371933","SSLC","MICRO TECH CNC PVT LTD U-4 CONTRACT","GAGE CHEAKING"],
  ["618","44400154","ANAND ABISHEK RAJASEKAR","Male","single","2005-09-30","2026-02-02","WORKER TRAINEE","UNIT 4","VMC MACHINE SHOP","JUNIOR OPERATING ENGINEER","PRODUCTION","ELECTRIC VEHICLE","9600225267","9600225267","anandabishek193@gmail.com","735496071273","0","FLBPR0067K","0","","0","500101014038710","ITI","",""],
  ["619","44400176","PRADEEP S","Male","single","2004-10-05","2026-05-06","WORKER TRAINEE","UNIT 4","WELDING","TRAINEE","ADMIN STAFF","ELECTRIC VEHICLE","","","","789065437654","0","0","0","","0","0","","",""],
  ["620","44400187","LOGANATHAN B","Male","single","2006-02-05","2026-07-20","WORKER TRAINEE","UNIT 4","MAINTENANCE","TRAINEE","ADMIN STAFF","COMMON","","","","346737838373","0","0","0","","0","0","","",""],
  ["621","44400194","RAVI SHANKAR SARAVANAN","Male","single","2004-06-09","2026-09-17","WORKER TRAINEE","UNIT 4","QUALITY","TRAINEE","ADMIN STAFF","COMMON","9342638550","9342638550","ravishankrsaravanan@gmail.com","722881908475","0","GVBPR3798Q","0","","0","0","B TECH","",""],
  ["622","44400195","SIVA N","Male","single","2004-01-20","2026-09-21","WORKER TRAINEE","UNIT 4","QUALITY","TRAINEE","ADMIN STAFF","COMMON","9363399692","9363399692","shiva20012004tamil@gmail.com","213555511603","0","DESPN7335J","0","","0","0","ITI","ASHOK LEYLAND","ASSAMBLY"],
  ["739","99900006","PONMANI P","Female","single","1998-04-15","2025-03-20","STAFF","MPIPL","ADMINISTRATION","SUPERVISOR-TRAINEE","ADMIN STAFF","PROFITAGRO","","","","","0","0","0","","0","0","","",""],
  ["740","99900010","KAVIARASAN GOVINDARASU","Male","single","1993-06-23","2025-08-06","STAFF","MPIPL","MANAFACTURING","TECHNICAL PROJECT MANAGER","ADMIN STAFF","PROFITAGRO","7373904558","7373904558","kgkavi786@gmail.com","356865945555","0","CQKPK2860C","TN31Z20140000459","","P7964568","0","B.E","",""],
  ["741","99900003","NAVEEN PERUMAL","Male","single","2001-07-29","2024-10-14","STAFF TRAINEE","MPIPL","AGRONOMY","TRAINEE","ADMIN STAFF","PROFITAGRO","9791204893","9791204893","naveenaveen15941@gmail.com","862372085407","0","0","0","","0","0","","",""],
  ["742","99900004","SAI SANGEETHA N","Female","married","1998-04-19","2024-11-05","STAFF TRAINEE","MPIPL","AGRONOMY","TRAINEE","ADMIN STAFF","PROFITAGRO","8248401207","8248401207","SAISANGEETHA1904@GMAIL.COM","","WYG1366152","KVTPS0981Q","","","","0","BSC","SRI RAM FINANCE","BUSINESS EXECUTIVE"],
  ["743","99900005","SANJAI B J","Male","single","1999-10-09","2025-01-02","STAFF TRAINEE","MPIPL","AGRONOMY","TRAINEE","ADMIN STAFF","PROFITAGRO","","","","","0","0","0","","0","0","","",""],
  ["744","99900007","ASHA RV","Female","single","2003-08-07","2025-04-07","STAFF TRAINEE","MPIPL","ADMINISTRATION","JUNIOR EXECUTIVE","ADMIN STAFF","PROFITAGRO","","","","","0","0","0","","0","0","","",""],
  ["745","99900013","AMARESH V","Male","single","1990-03-15","2025-10-29","WORKER","MPIPL","DRIVER","DRIVER","PRODUCTION","PROFITAGRO","","","","777491038693","0","0","0","","0","0","","",""],
  ["746","99900015","SENTHILKUMAR GOVINDHARAJ","Male","married","1980-09-11","2025-12-08","WORKER","MPIPL","DRIVER","DRIVER","PRODUCTION","PROFITAGRO","9894801363","9894801363","senthil271079@gmail.com","","0","0","0","","0","0","","",""],
  ["747","99900016","THAMIZHARASAN M","Male","single","1996-06-10","2026-08-21","WORKER","MPIPL","AGRONOMY","HELPER","ADMIN STAFF","COMMON","","","","","0","0","0","","0","0","","",""],
  ["748","11100223","CHANDRU S","Male","single","2002-10-03","2024-07-22","WORKER TRAINEE","MPIPL","MAINTENANCE","TRAINEE","ADMIN STAFF","PROFITAGRO","6383550347","6383550347","chandrusurya638355@gmail.com","286699647815","0","SVFPS8246N","0","","0","500101013877729","","",""]
];
module.exports = function createApiRouter({ jwtSecret }) {
  const JWT_SECRET = jwtSecret;
  const DEPARTMENT_AUTH_DIR = process.env.MT_DEPARTMENT_AUTH_DIR
    ? path.resolve(process.env.MT_DEPARTMENT_AUTH_DIR)
    : path.resolve(__dirname, 'runtime');
  const DEPARTMENT_AUTH_FILE = path.join(DEPARTMENT_AUTH_DIR, 'department-auth.json');
  const DEPARTMENT_AUDIT_FILE = path.join(DEPARTMENT_AUTH_DIR, 'department-audit.jsonl');
  const DEPARTMENT_FOLDER_BY_KEY = Object.freeze({ hr: 'HR', marketing: 'Marketing', quality: 'Quality', canteen: 'canteen' });
  const DEPARTMENT_CATEGORY_BY_KEY = Object.freeze({ hr: 'HR', marketing: 'Marketing', quality: 'Quality', canteen: 'Canteen' });
  const DEPARTMENT_KEY_BY_CATEGORY = Object.freeze({ HR: 'hr', Marketing: 'marketing', Quality: 'quality', Canteen: 'canteen' });
  const DEPARTMENT_PASSWORD_MIN = 12;
  const DEPARTMENT_BCRYPT_HASH = /^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$/;
  const seedDepartmentAuth = () => ({ accounts: Object.fromEntries(Object.entries(DEPARTMENT_AUTH_DEFINITIONS).map(([key, def]) => [key, {
    userId: def.userId, passwordHash: def.passwordHash, mustChange: false, tokenVersion: 0
  }])) });
  const saveDepartmentAuth = (state) => {
    fs.mkdirSync(DEPARTMENT_AUTH_DIR, { recursive: true });
    const safeState = { accounts: {} };
    for (const [key, def] of Object.entries(DEPARTMENT_AUTH_DEFINITIONS)) {
      const account = state.accounts[key];
      if (!account || account.userId !== def.userId || !DEPARTMENT_BCRYPT_HASH.test(account.passwordHash) ||
          typeof account.mustChange !== 'boolean' || !Number.isSafeInteger(account.tokenVersion) || account.tokenVersion < 0) {
        throw new Error('Department authentication state is invalid.');
      }
      safeState.accounts[key] = { userId: account.userId, passwordHash: account.passwordHash, mustChange: account.mustChange, tokenVersion: account.tokenVersion };
    }
    const temp = path.join(DEPARTMENT_AUTH_DIR, `department-auth.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`);
    fs.writeFileSync(temp, JSON.stringify(safeState, null, 2) + '\n', { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    try { fs.renameSync(temp, DEPARTMENT_AUTH_FILE); }
    catch (err) { try { fs.unlinkSync(temp); } catch (_) {} throw err; }
  };
  const loadDepartmentAuth = () => {
    fs.mkdirSync(DEPARTMENT_AUTH_DIR, { recursive: true });
    if (!fs.existsSync(DEPARTMENT_AUTH_FILE)) {
      const initial = seedDepartmentAuth();
      saveDepartmentAuth(initial);
      return initial;
    }
    let state;
    try { state = JSON.parse(fs.readFileSync(DEPARTMENT_AUTH_FILE, 'utf8')); }
    catch (_) { throw new Error('Department authentication file is unreadable or invalid JSON.'); }
    for (const [key, def] of Object.entries(DEPARTMENT_AUTH_DEFINITIONS)) {
      const account = state && state.accounts && state.accounts[key];
      if (!account || account.userId !== def.userId || !DEPARTMENT_BCRYPT_HASH.test(account.passwordHash) ||
          typeof account.mustChange !== 'boolean' || !Number.isSafeInteger(account.tokenVersion) || account.tokenVersion < 0) {
        throw new Error('Department authentication state is invalid; repair runtime/department-auth.json before starting the backend.');
      }
    }
    return state;
  };
  const departmentAuthState = loadDepartmentAuth();
  const auditDepartmentAction = async ({ actor, department, action, affectedRecord }) => {
    const entry = { timestamp: new Date().toISOString(), account: String(actor), department: String(department), action: String(action), affectedRecord: String(affectedRecord || '-') };
    await fs.promises.appendFile(DEPARTMENT_AUDIT_FILE, JSON.stringify(entry) + '\n', { encoding: 'utf8', mode: 0o600 });
  };
  const readCookie = (req, name) => {
    const prefix = name + '=';
    const item = (req.headers.cookie || '').split(';').map((part) => part.trim()).find((part) => part.startsWith(prefix));
    return item ? item.slice(prefix.length) : '';
  };
  const departmentSessionFromRequest = (req) => {
    const token = readCookie(req, 'mt_dept_session');
    if (!token) return null;
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const key = decoded && decoded.department_key;
      const def = DEPARTMENT_AUTH_DEFINITIONS[key];
      const account = departmentAuthState.accounts[key];
      if (decoded.auth_source !== 'department' || decoded.role !== 'department' || !def ||
          decoded.id !== def.userId || account.userId !== decoded.id || decoded.tokenVersion !== account.tokenVersion) return null;
      return { key, department: def.department, folder: DEPARTMENT_FOLDER_BY_KEY[key], category: DEPARTMENT_CATEGORY_BY_KEY[key], userId: account.userId, mustChange: account.mustChange };
    } catch (_) { return null; }
  };
  const departmentSessionCookie = (token) => {
    const secure = process.env.COOKIE_SECURE === 'true' ? '; Secure' : '';
    return `mt_dept_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800${secure}`;
  };
  const departmentLogoutCookie = () => {
    const secure = process.env.COOKIE_SECURE === 'true' ? '; Secure' : '';
    return `mt_dept_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`;
  };
  const verifyDepartmentSessionIfPresent = (req, res, next) => { req.departmentSession = departmentSessionFromRequest(req); next(); };
  const requireDepartmentSession = (req, res, next) => req.departmentSession
    ? next() : res.status(401).json({ success: false, message: 'Department login required.' });
  const requireCircularManager = (req, res, next) => {
    if (req.user && req.user.role === 'admin') return next();
    if (req.departmentSession && !req.departmentSession.mustChange) return next();
    return res.status(403).json({ success: false, message: 'Department login is required to manage this section.' });
  };
  const canManageCircularFolder = (req, folder) => !!(req.user && req.user.role === 'admin') ||
    !!(req.departmentSession && !req.departmentSession.mustChange && req.departmentSession.folder === folder);
  const departmentFolderForCategory = (category) => CIRCULAR_CATEGORY_FOLDERS[category] || null;
  const canManageAnnouncement = (req, item) => {
    if (req.user && req.user.role === 'admin') return true;
    if (!req.departmentSession || req.departmentSession.mustChange) return false;
    const categoryFolder = departmentFolderForCategory(item && item.category);
    const attachmentFolder = typeof (item && item.attachment_path) === 'string' ? item.attachment_path.split('/')[0] : null;
    return req.departmentSession.folder === categoryFolder || req.departmentSession.folder === attachmentFolder;
  };
  const departmentPasswordIsStrong = (value) => typeof value === 'string' && Buffer.byteLength(value, 'utf8') >= DEPARTMENT_PASSWORD_MIN && Buffer.byteLength(value, 'utf8') <= 72 && /[A-Za-z]/.test(value) && /\d/.test(value) && /[^A-Za-z0-9]/.test(value);
  const verifyToken = async (req, res, next) => {
    const header = req.headers.authorization;
    const cookie = (req.headers.cookie || '').split(';').map((part) => part.trim()).find((part) => part.startsWith('mt_session='));
    const cookieToken = cookie ? cookie.slice('mt_session='.length) : '';
    const parts = header ? header.split(' ') : [];
    const token = parts.length === 2 && parts[0] === 'Bearer' ? parts[1] : cookieToken;
    if (!token) return res.status(401).json({ success: false, message: 'Authentication required.' });
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const account = decoded.auth_source === 'static' ? staticAccountById.get(decoded.id) : null;
      if (!account || account.status !== 'active' || decoded.role !== account.role) return res.status(403).json({ success: false, message: 'Account is inactive or unavailable.' });
      req.user = { ...decoded, role: account.role, status: account.status };
      next();
    } catch (err) {
      if (err.name === 'TokenExpiredError') return res.status(401).json({ success: false, expired: true, message: 'Session expired. Please log in again.' });
      return res.status(401).json({ success: false, message: 'Session expired or invalid. Please log in again.' });
    }
  };
  const requireAdmin = (req, res, next) => {
    if (!req.user || req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Access denied. Administrator privileges required.' });
    next();
  };
  const loginLimiter = makeRateLimiter(10, 15 * 60 * 1000);
  const recoveryLimiter = makeRateLimiter(5, 15 * 60 * 1000);
  const otpDigest = (userId, otp) => crypto.createHmac('sha256', JWT_SECRET).update(`${userId}:${otp}`).digest('hex').slice(0, 10);
  const escapeHtml = (value) => String(value == null ? '' : value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[char]));
  const sessionCookie = (token, persistent = false) => {
    // Secure must follow the browser-facing IIS scheme, not the internal HTTP
    // hop from ARR to Node. Set COOKIE_SECURE=true only when IIS uses HTTPS.
    const secure = process.env.COOKIE_SECURE === 'true' ? '; Secure' : '';
    const age = persistent ? '; Max-Age=604800' : '';
    return `mt_session=${token}; Path=/; HttpOnly; SameSite=Strict${secure}${age}`;
  };
  const api = express.Router();
  api.use((req, res, next) => {
    // Circular attachments are sent as raw bytes. application/octet-stream is not a
    // type other websites can send without a CORS preflight, so this stays protected.
    if (req.method === 'POST' && req.path === '/announcements/attachment' && req.is('application/octet-stream')) return next();
    if (['POST', 'PUT', 'PATCH'].includes(req.method) &&
        req.path !== '/auth/logout' &&
        (!req.is('application/json') || !req.body || typeof req.body !== 'object' || Array.isArray(req.body))) {
      return res.status(415).json({ success: false, message: 'A JSON object request body is required.' });
    }
    next();
  });
  const authRouter = (() => {
    const router = express.Router();

    // POST /api/auth/login
    router.post('/login', loginLimiter, async (req, res) => {
      try {
        const rawEmpId = req.body.employee_id || req.body.emp_id || req.body.username;
        const { password } = req.body;

        if (!rawEmpId) {
          return res.status(400).json({ success: false, message: 'User ID is required.' });
        }

        if (typeof rawEmpId !== 'string' || rawEmpId.trim().length > 120) {
          return res.status(400).json({ success: false, message: 'Enter a valid User ID.' });
        }
        const loginId = rawEmpId.trim();

        if (typeof password !== 'string' || password.length < 1 || Buffer.byteLength(password, 'utf8') > 72) {
          return res.status(400).json({ success: false, message: 'Password is required.' });
        }

        const staticUser = STATIC_ACCOUNTS.find((account) =>
            account.emp_id === loginId || account.username.toLowerCase() === loginId.toLowerCase()
        );
        if (!staticUser) return res.status(401).json({ success: false, message: 'Invalid Employee ID or password.' });
        const user = staticUser;

        // Check account status before verifying password
        if (user.status !== 'active' || user.is_active === 0 || user.is_active === false) {
          return res.status(403).json({
            success: false,
            message: 'Account is inactive. Please contact HR or plant administration.'
          });
        }

        // Verify password with bcrypt
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) {
          return res.status(401).json({ success: false, message: 'Invalid Employee ID or password.' });
        }

        const tokenPayload = {
          id: user.id,
          emp_id: user.emp_id,
          username: user.username,
          email: user.email,
          full_name: user.full_name,
          role: user.role,
          status: user.status || 'active',
          phone_ext: user.phone_ext,
          department: user.department,
          shift: user.shift,
          auth_source: 'static'
        };

        const remember = req.body.remember_me === true;
        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: remember ? '7d' : '8h' });
        res.setHeader('Set-Cookie', sessionCookie(token, remember));
        res.setHeader('Cache-Control', 'no-store');

        const responseUser = { ...tokenPayload };
        delete responseUser.auth_source;
        res.json({
          success: true,
          message: 'Login successful',
          user: responseUser
        });
      } catch (err) {
        console.error('Login request failed.');
        res.status(500).json({ success: false, message: 'Internal server error during login.' });
      }
    });

    // POST /api/auth/guest - employees open the portal directly, no user name or password.
    // Issues the standard employee session; only the Admin account needs a password.
    router.post('/guest', (req, res) => {
      const account = staticAccountById.get('static-employee');
      const payload = { id: account.id, emp_id: account.emp_id, username: account.username, full_name: account.full_name, role: account.role, status: account.status, auth_source: 'static' };
      const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
      res.setHeader('Set-Cookie', sessionCookie(token, true));
      res.setHeader('Cache-Control', 'no-store');
      const user = { ...payload }; delete user.auth_source;
      res.json({ success: true, user });
    });

    router.post('/logout', (req, res) => {
      const secure = process.env.COOKIE_SECURE === 'true' ? '; Secure' : '';
      res.setHeader('Set-Cookie', `mt_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`);
      res.setHeader('Cache-Control', 'no-store');
      res.json({ success: true, message: 'Logged out.' });
    });

    // GET /api/auth/me
    router.get('/me', verifyToken, async (req, res) => {
      try {
        const account = staticAccountById.get(req.user.id);
        if (!account) return res.status(404).json({ success: false, message: 'User not found.' });
        res.json({ success: true, user: { id: account.id, username: account.username, emp_id: account.emp_id, email: '', full_name: account.full_name, role: account.role, status: account.status, phone_ext: '', department: '', shift: '', created_at: null } });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to fetch user profile.' });
      }
    });

    // POST /api/auth/forgot-password
    router.post('/forgot-password', recoveryLimiter, (req, res) => {
      const { identifier } = req.body;
      if (typeof identifier !== 'string' || !identifier.trim() || identifier.trim().length > 254) {
        return res.status(400).json({ success: false, message: 'Employee ID or registered Email is required.' });
      }
      return res.status(503).json({ success: false, message: 'Password recovery is not configured for code-managed accounts. Contact the administrator to update the server-side bcrypt hash.' });
    });

    // POST /api/auth/reset-password
    router.post('/reset-password', recoveryLimiter, (req, res) => {
      const { identifier, otp, newPassword } = req.body;
      if (typeof identifier !== 'string' || !identifier.trim() || identifier.trim().length > 254 ||
          typeof otp !== 'string' || !/^\d{6}$/.test(otp) || typeof newPassword !== 'string') {
        return res.status(400).json({ success: false, message: 'Employee ID/Email, OTP, and new password are required.' });
      }
      if (newPassword.length < 8 || Buffer.byteLength(newPassword, 'utf8') > 72) {
        return res.status(400).json({ success: false, message: 'Password must be 8 to 72 bytes long.' });
      }
      return res.status(503).json({ success: false, message: 'Password reset is not configured for code-managed accounts. Contact the administrator to update the server-side bcrypt hash.' });
    });


    return router;
  })();
  api.use('/auth', authRouter);

  // Department sessions are separate from the employee/Admin cookie and only
  // grant circular management rights in the account's mapped department.
  const departmentAuthRouter = (() => {
    const router = express.Router();
    router.post('/login', verifyToken, loginLimiter, async (req, res) => {
      const { department, userId, password } = req.body || {};
      const key = String(department || '').toLowerCase();
      const def = DEPARTMENT_AUTH_DEFINITIONS[key];
      const account = departmentAuthState.accounts[key];
      if (!def || !account || typeof userId !== 'string' || typeof password !== 'string' || Buffer.byteLength(password, 'utf8') > 72) return res.status(401).json({ success: false, message: 'Invalid department User ID or password.' });
      try {
        if (userId.trim() !== account.userId || !(await bcrypt.compare(password, account.passwordHash))) return res.status(401).json({ success: false, message: 'Invalid department User ID or password.' });
        const token = jwt.sign({ id: account.userId, role: 'department', auth_source: 'department', department_key: key, tokenVersion: account.tokenVersion }, JWT_SECRET, { expiresIn: '8h', issuer: 'mt-cnc-intranet' });
        res.setHeader('Set-Cookie', departmentSessionCookie(token));
        await auditDepartmentAction({ actor: account.userId, department: def.department, action: 'login', affectedRecord: '-' });
        return res.json({ success: true, user: { department: def.department, mustChange: account.mustChange } });
      } catch (_) { return res.status(500).json({ success: false, message: 'Department sign-in failed.' }); }
    });
    router.get('/status', verifyToken, verifyDepartmentSessionIfPresent, (req, res) => {
      const s = req.departmentSession;
      res.json({ success: true, authenticated: !!s, user: s ? { department: s.department, mustChange: s.mustChange } : null });
    });
    router.post('/change-password', verifyToken, verifyDepartmentSessionIfPresent, requireDepartmentSession, async (req, res) => {
      const { password } = req.body || {};
      if (!departmentPasswordIsStrong(password)) return res.status(400).json({ success: false, message: 'Use at least 12 characters with a letter, number and symbol.' });
      try {
        const account = departmentAuthState.accounts[req.departmentSession.key];
        account.passwordHash = await bcrypt.hash(password, 12);
        account.mustChange = false;
        account.tokenVersion += 1;
        saveDepartmentAuth(departmentAuthState);
        const token = jwt.sign({ id: account.userId, role: 'department', auth_source: 'department', department_key: req.departmentSession.key, tokenVersion: account.tokenVersion }, JWT_SECRET, { expiresIn: '8h', issuer: 'mt-cnc-intranet' });
        res.setHeader('Set-Cookie', departmentSessionCookie(token));
        await auditDepartmentAction({ actor: account.userId, department: req.departmentSession.department, action: 'password_changed', affectedRecord: '-' });
        return res.json({ success: true, user: { department: req.departmentSession.department, mustChange: false } });
      } catch (_) { return res.status(500).json({ success: false, message: 'The password could not be changed.' }); }
    });
    router.post('/logout', verifyToken, verifyDepartmentSessionIfPresent, async (req, res) => {
      if (req.departmentSession) {
        await auditDepartmentAction({ actor: req.departmentSession.userId, department: req.departmentSession.department, action: 'logout', affectedRecord: '-' }).catch(() => {});
        const account = departmentAuthState.accounts[req.departmentSession.key];
        account.tokenVersion += 1;
        try { saveDepartmentAuth(departmentAuthState); } catch (_) {}
      }
      res.setHeader('Set-Cookie', departmentLogoutCookie());
      return res.json({ success: true });
    });
    router.post('/:department/reset-password', verifyToken, requireAdmin, async (req, res) => {
      const key = String(req.params.department || '').toLowerCase();
      const account = departmentAuthState.accounts[key];
      const { password } = req.body || {};
      if (!account) return res.status(404).json({ success: false, message: 'Department account not found.' });
      if (!departmentPasswordIsStrong(password)) return res.status(400).json({ success: false, message: 'Use at least 12 characters with a letter, number and symbol.' });
      try {
        account.passwordHash = await bcrypt.hash(password, 12);
        account.mustChange = true;
        account.tokenVersion += 1;
        saveDepartmentAuth(departmentAuthState);
        await auditDepartmentAction({ actor: req.user.id, department: DEPARTMENT_AUTH_DEFINITIONS[key].department, action: 'password_reset', affectedRecord: '-' });
        return res.json({ success: true, message: 'Password reset; the department account must change it at next sign-in.' });
      } catch (_) { return res.status(500).json({ success: false, message: 'The department password could not be reset.' }); }
    });
    return router;
  })();
  api.use('/department-auth', departmentAuthRouter);

  const boardRouter = (() => {
    const router = express.Router();

    // GET /api/board
    router.get('/', async (req, res) => {
      res.json({ success: true, data: { board: MEMORY.board, shifts: [], emergency: [] } });
    });

    // PUT /api/board (Admin only)
    router.put('/', verifyToken, requireAdmin, async (req, res) => {
      try {
        const {
          last_incident_date,
          incident_free_target,
          on_time_delivery,
          delivery_note,
          machines_down,
          machines_note
        } = req.body;

        const target = Number(incident_free_target);
        if (!validIsoDate(last_incident_date) ||
            !Number.isInteger(target) || target < 1 || target > 3650 ||
            (on_time_delivery != null && (typeof on_time_delivery !== 'string' || !/^\d{1,3}(?:\.\d{1,2})?%$/.test(on_time_delivery) || Number(on_time_delivery.slice(0, -1)) > 100)) ||
            !validText(delivery_note == null ? '' : delivery_note, 100, true) ||
            !validText(machines_down == null ? '' : machines_down, 20, true) ||
            !validText(machines_note == null ? '' : machines_note, 120, true)) {
          return res.status(400).json({ success: false, message: 'Invalid shop floor board values.' });
        }

        const updatedBoard = MEMORY.board = {
          last_incident_date,
          incident_free_target: target,
          on_time_delivery: on_time_delivery || 'Not configured',
          delivery_note: delivery_note || '',
          machines_down: machines_down || 'Not configured',
          machines_note: machines_note || ''
        };

        // Emit Socket.IO real-time update
        if (req.app.get('io')) {
          req.app.get('io').emit('board:updated', updatedBoard);
        }

        res.json({ success: true, message: 'Shop floor figures updated for this server run.', data: updatedBoard });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to update shop floor board figures.' });
      }
    });


    return router;
  })();
  api.use('/board', boardRouter);

  const announcementsRouter = (() => {
    const router = express.Router();
    router.param('id', validRowId);

    // GET /api/announcements
    router.get('/', verifyToken, async (req, res) => {
      try {
        const rows = MEMORY.announcements.slice().sort((a, b) => Number(b.is_pinned) - Number(a.is_pinned) || String(b.posted_date).localeCompare(String(a.posted_date)) || b.id - a.id);
        res.json({ success: true, data: rows });
      } catch (err) { res.status(500).json({ success: false, message: 'Failed to retrieve announcements.' }); }
    });

    // POST /api/announcements/attachment - raw file body; scoped to a department.
    // Headers: X-File-Name (URL-encoded) and X-Category. Saves the file into
    // the Circulars folder of that department and returns its path.
    router.post('/attachment', verifyToken, verifyDepartmentSessionIfPresent, requireCircularManager,
      express.raw({ type: 'application/octet-stream', limit: CIRCULAR_ATTACH_MAX }), async (req, res) => {
        try {
          let original = '';
          try { original = decodeURIComponent(String(req.get('X-File-Name') || '')); } catch (_) { original = ''; }
          const name = original;
          const ext = path.extname(name).toLowerCase();
          const category = req.get('X-Category');
          const folder = Object.prototype.hasOwnProperty.call(CIRCULAR_CATEGORY_FOLDERS, category)
            ? CIRCULAR_CATEGORY_FOLDERS[category] : null;
          if (!Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).json({ success: false, message: 'No file was received.' });
          if (!folder) return res.status(400).json({ success: false, message: 'Choose a valid department.' });
          if (!canManageCircularFolder(req, folder)) return res.status(403).json({ success: false, message: 'You can upload files only to your department.' });
          if (!name || name.length > 120 || name !== path.basename(name) || name.trim() !== name ||
              /[\\/:*?"<>|\x00-\x1f]/.test(name) || /[. ]$/.test(name) || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(name)) {
            return res.status(400).json({ success: false, message: 'Use a valid filename without folder paths or unsupported characters.' });
          }
          if (!DEPARTMENT_DOC_TYPES[ext]) return res.status(400).json({ success: false, message: 'Attach a PDF, Word, Excel, PowerPoint, JPG or PNG file.' });
          if (!fileLooksLike(ext, req.body)) return res.status(400).json({ success: false, message: 'The file content does not match its type (' + ext + ').' });
          const dir = path.resolve(CIRCULAR_ATTACH_ROOT, folder);
          const inside = path.relative(CIRCULAR_ATTACH_ROOT, dir);
          if (!inside || inside.startsWith('..') || path.isAbsolute(inside)) return res.status(400).json({ success: false, message: 'Invalid department folder.' });
          let fileName = name;
          try {
            const [rootStat, dirStat] = await Promise.all([fs.promises.lstat(CIRCULAR_ATTACH_ROOT), fs.promises.lstat(dir)]);
            if (!rootStat.isDirectory() || rootStat.isSymbolicLink() || !dirStat.isDirectory() || dirStat.isSymbolicLink()) {
              return res.status(503).json({ success: false, message: 'The existing department folder is unavailable.' });
            }
            const extName = path.extname(name);
            const baseName = path.basename(name, extName);
            let saved = false;
            for (let n = 1; n <= 1000; n++) {
              fileName = n === 1 ? name : `${baseName} (${n})${extName}`;
              try { await fs.promises.writeFile(path.join(dir, fileName), req.body, { flag: 'wx' }); saved = true; break; }
              catch (e) {
                if (e.code !== 'EEXIST') throw e;
              }
            }
            if (!saved) return res.status(409).json({ success: false, message: 'A unique filename could not be chosen. Rename the file and try again.' });
          } catch (err) {
            console.error('Circular attachment save failed:', err && err.code);
            const why = err && (err.code === 'EACCES' || err.code === 'EPERM') ? 'The server is not allowed to write to the Circulars folder.' : 'The Circulars folder could not be reached.';
            return res.status(503).json({ success: false, code: err && err.code, message: why });
          }
          await auditDepartmentAction({ actor: req.departmentSession ? req.departmentSession.userId : req.user.id, department: req.departmentSession ? req.departmentSession.department : 'All', action: 'file_upload', affectedRecord: folder + '/' + fileName });
          res.status(201).json({ success: true, data: { path: folder + '/' + fileName, name: fileName, size: req.body.length } });
        } catch (err) {
          res.status(500).json({ success: false, message: 'The attachment could not be saved.' });
        }
      });
    router.use('/attachment', (err, req, res, next) => {
      if (err && err.type === 'entity.too.large') return res.status(413).json({ success: false, message: 'The file is larger than 20 MB.' });
      next(err);
    });

    // POST /api/announcements; department accounts may publish only to their own category.
    router.post('/', verifyToken, verifyDepartmentSessionIfPresent, requireCircularManager, async (req, res) => {
      try {
        const { category, headline, body, is_pinned, attachment_path, attachment_name } = req.body;
        let attachment = null;
        if (attachment_path != null && attachment_path !== '') {
          const full = typeof attachment_path === 'string' ? resolveDepartmentFile(CIRCULAR_ATTACH_ROOT, attachment_path) : null;
          let exists = false;
          if (full) { try { exists = (await fs.promises.stat(full)).isFile(); } catch (_) { exists = false; } }
          if (!exists) return res.status(400).json({ success: false, message: 'The attachment was not found in the Circulars folder.' });
          attachment = { path: attachment_path, name: cleanFileName(attachment_name) || path.basename(full) };
        }
        const categories = CIRCULAR_CATEGORIES;
        if (!validText(headline, 160) || (body != null && !validText(body, 10000, true)) ||
            (category != null && !categories.includes(category)) ||
            (is_pinned != null && ![true, false, 0, 1].includes(is_pinned))) {
          return res.status(400).json({ success: false, message: 'Invalid announcement details.' });
        }
        const cat = category || 'General';
        if (!canManageCircularFolder(req, departmentFolderForCategory(cat))) return res.status(403).json({ success: false, message: 'You can publish circulars only for your department.' });
        if (attachment && !canManageCircularFolder(req, attachment.path.split('/')[0])) return res.status(403).json({ success: false, message: 'The attachment must belong to your department.' });

        const posted_date = new Date().toISOString().slice(0, 10);
        const pinned = is_pinned ? 1 : 0;
        const bodyText = (body || '').trim();

        const newAnnouncement = {
          id: nextId(MEMORY.announcements),
          category: cat,
          headline: headline.trim(),
          body: bodyText,
          is_pinned: pinned,
          posted_date,
          created_at: new Date().toISOString(),
          created_by: req.user.id
        };
        if (attachment) { newAnnouncement.attachment_path = attachment.path; newAnnouncement.attachment_name = attachment.name; }
        await auditDepartmentAction({ actor: req.departmentSession ? req.departmentSession.userId : req.user.id, department: req.departmentSession ? req.departmentSession.department : cat, action: 'circular_create', affectedRecord: `${newAnnouncement.id}:${newAnnouncement.headline}` });
        MEMORY.announcements.push(newAnnouncement);

        // Emit Socket.IO
        if (req.app.get('io')) {
          req.app.get('io').emit('announcement:created', newAnnouncement);
        }

        res.status(201).json({ success: true, message: 'Announcement posted successfully.', data: newAnnouncement });
      } catch (err) {
        console.error('Post announcement error:', err);
        res.status(500).json({ success: false, message: 'Failed to post announcement.' });
      }
    });

    // PATCH /api/announcements/:id/pin
    router.patch('/:id/pin', verifyToken, verifyDepartmentSessionIfPresent, requireCircularManager, async (req, res) => {
      try {
        const id = req.params.id;
        const { is_pinned } = req.body;
        if (![true, false, 0, 1].includes(is_pinned)) {
          return res.status(400).json({ success: false, message: 'Invalid pin value.' });
        }

        const announcement = MEMORY.announcements.find((item) => String(item.id) === String(id));
        if (!announcement) return res.status(404).json({ success: false, message: 'Announcement not found.' });
        if (!canManageAnnouncement(req, announcement)) return res.status(403).json({ success: false, message: 'You can manage circulars only in your department.' });
        announcement.is_pinned = is_pinned ? 1 : 0;

        if (req.app.get('io')) {
          req.app.get('io').emit('announcement:pinned', { id, is_pinned: is_pinned ? 1 : 0 });
        }

        res.json({ success: true, message: 'Announcement pin status updated.' });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to update announcement.' });
      }
    });

    // PUT /api/announcements/:id edits headline and body only; department/category/file are immutable.
    router.put('/:id', verifyToken, verifyDepartmentSessionIfPresent, requireCircularManager, async (req, res) => {
      const announcement = MEMORY.announcements.find((item) => String(item.id) === String(req.params.id));
      if (!announcement) return res.status(404).json({ success: false, message: 'Announcement not found.' });
      if (!canManageAnnouncement(req, announcement)) return res.status(403).json({ success: false, message: 'You can edit circulars only in your department.' });
      const { headline, body } = req.body || {};
      if (!validText(headline, 160) || (body != null && !validText(body, 10000, true))) return res.status(400).json({ success: false, message: 'Invalid circular details.' });
      announcement.headline = headline.trim();
      announcement.body = (body || '').trim();
      announcement.updated_at = new Date().toISOString();
      try { await auditDepartmentAction({ actor: req.departmentSession ? req.departmentSession.userId : req.user.id, department: announcement.category || 'General', action: 'circular_edit', affectedRecord: `${announcement.id}:${announcement.headline}` }); }
      catch (_) { return res.status(503).json({ success: false, message: 'Audit log is unavailable; the circular was updated but the audit entry failed.' }); }
      if (req.app.get('io')) req.app.get('io').emit('announcement:created', announcement);
      return res.json({ success: true, data: announcement });
    });

    // DELETE /api/announcements/:id
    router.delete('/:id', verifyToken, verifyDepartmentSessionIfPresent, requireCircularManager, async (req, res) => {
      try {
        const id = req.params.id;
        const index = MEMORY.announcements.findIndex((item) => String(item.id) === String(id));
        if (index < 0) return res.status(404).json({ success: false, message: 'Announcement not found.' });
        const announcement = MEMORY.announcements[index];
        if (!canManageAnnouncement(req, announcement)) return res.status(403).json({ success: false, message: 'You can delete circulars only in your department.' });
        let attachmentDeleted = false;
        const attachmentPath = typeof announcement.attachment_path === 'string' ? announcement.attachment_path : '';
        const attachmentParts = attachmentPath.split('/');
        if (path.extname(attachmentPath).toLowerCase() === '.pdf' && attachmentParts.length === 2 && CIRCULAR_DEPARTMENT_FOLDERS.includes(attachmentParts[0])) {
          const full = resolveDepartmentFile(CIRCULAR_ATTACH_ROOT, attachmentPath);
          const referencedElsewhere = MEMORY.announcements.some((item, itemIndex) => itemIndex !== index && item.attachment_path === attachmentPath);
          if (full && !referencedElsewhere) {
            try {
              const [folderStat, fileStat] = await Promise.all([
                fs.promises.lstat(path.join(CIRCULAR_ATTACH_ROOT, attachmentParts[0])),
                fs.promises.lstat(full)
              ]);
              if (!folderStat.isDirectory() || folderStat.isSymbolicLink() || !fileStat.isFile() || fileStat.isSymbolicLink()) {
                return res.status(503).json({ success: false, message: 'The attached PDF could not be safely removed; the circular was kept.' });
              }
              await fs.promises.unlink(full);
              attachmentDeleted = true;
            } catch (err) {
              if (err && err.code !== 'ENOENT') {
                console.error('Circular PDF removal failed:', err && err.code);
                return res.status(503).json({ success: false, message: 'The attached PDF could not be removed; the circular was kept.' });
              }
            }
          }
        }
        await auditDepartmentAction({ actor: req.departmentSession ? req.departmentSession.userId : req.user.id, department: announcement.category || 'General', action: 'circular_delete', affectedRecord: `${announcement.id}:${announcement.headline}` });
        MEMORY.announcements.splice(index, 1);

        // Emit Socket.IO
        if (req.app.get('io')) {
          req.app.get('io').emit('announcement:deleted', { id });
        }

        res.json({ success: true, message: 'Announcement deleted successfully.', attachmentDeleted });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to delete announcement.' });
      }
    });


    return router;
  })();
  api.use('/announcements', announcementsRouter);

  const circularManagementRouter = (() => {
    const router = express.Router();
    router.patch('/file', verifyToken, verifyDepartmentSessionIfPresent, requireCircularManager, async (req, res) => {
      const { path: relPath, name } = req.body || {};
      const parts = typeof relPath === 'string' ? relPath.split('/') : [];
      const source = resolveDepartmentFile(CIRCULAR_ATTACH_ROOT, relPath);
      if (parts.length !== 2 || !CIRCULAR_DEPARTMENT_FOLDERS.includes(parts[0]) || !source || !canManageCircularFolder(req, parts[0])) return res.status(403).json({ success: false, message: 'You can rename files only in your department.' });
      const oldName = path.basename(source);
      if (typeof name !== 'string' || !name.trim() || name.length > 120 || name !== path.basename(name) || /[\\/:*?"<>|\x00-\x1f]/.test(name) || /[. ]$/.test(name) || path.extname(name).toLowerCase() !== path.extname(oldName).toLowerCase()) return res.status(400).json({ success: false, message: 'Enter a valid filename with the same file extension.' });
      const target = path.join(path.dirname(source), name.trim());
      try {
        const stat = await fs.promises.lstat(source);
        if (!stat.isFile() || stat.isSymbolicLink()) return res.status(404).json({ success: false, message: 'File not found.' });
        await fs.promises.copyFile(source, target, fs.constants.COPYFILE_EXCL);
        await fs.promises.unlink(source);
        const newRelPath = parts[0] + '/' + name.trim();
        for (const item of MEMORY.announcements) if (item.attachment_path === relPath) { item.attachment_path = newRelPath; item.attachment_name = name.trim(); }
        await auditDepartmentAction({ actor: req.departmentSession ? req.departmentSession.userId : req.user.id, department: req.departmentSession ? req.departmentSession.department : parts[0], action: 'file_rename', affectedRecord: `${relPath} -> ${newRelPath}` });
        if (req.app.get('io')) req.app.get('io').emit('announcement:created', { changed_file: newRelPath });
        return res.json({ success: true, data: { path: newRelPath, name: name.trim() } });
      } catch (err) {
        if (err.code === 'EEXIST') return res.status(409).json({ success: false, message: 'A file with that name already exists.' });
        return res.status(err.code === 'ENOENT' ? 404 : 503).json({ success: false, message: 'The file could not be renamed.' });
      }
    });
    router.delete('/file', verifyToken, verifyDepartmentSessionIfPresent, requireCircularManager, async (req, res) => {
      const relPath = typeof req.query.path === 'string' ? req.query.path : '';
      const parts = relPath.split('/');
      const full = resolveDepartmentFile(CIRCULAR_ATTACH_ROOT, relPath);
      if (parts.length !== 2 || !CIRCULAR_DEPARTMENT_FOLDERS.includes(parts[0]) || !full || !canManageCircularFolder(req, parts[0])) return res.status(403).json({ success: false, message: 'You can delete files only in your department.' });
      if (MEMORY.announcements.some((item) => item.attachment_path === relPath)) return res.status(409).json({ success: false, message: 'This file is attached to a circular. Delete the circular to remove both together.' });
      try {
        const stat = await fs.promises.lstat(full);
        if (!stat.isFile() || stat.isSymbolicLink()) return res.status(404).json({ success: false, message: 'File not found.' });
        await auditDepartmentAction({ actor: req.departmentSession ? req.departmentSession.userId : req.user.id, department: req.departmentSession ? req.departmentSession.department : parts[0], action: 'file_delete', affectedRecord: relPath });
        await fs.promises.unlink(full);
        return res.json({ success: true });
      } catch (err) { return res.status(err.code === 'ENOENT' ? 404 : 503).json({ success: false, message: 'The file could not be deleted.' }); }
    });
    return router;
  })();
  api.use('/circular-management', circularManagementRouter);

  const eventsRouter = (() => {
    const router = express.Router();
    router.param('id', validRowId);

    // GET /api/events
    router.get('/', verifyToken, async (req, res) => {
      res.json({ success: true, data: MEMORY.events.slice().sort((a, b) => String(a.event_date).localeCompare(String(b.event_date)) || a.id - b.id) });
    });

    // POST /api/events (Admin only)
    router.post('/', verifyToken, requireAdmin, async (req, res) => {
      try {
        const { event_date, title, place_and_time } = req.body;
        if (!validIsoDate(event_date) || !validText(title, 120) ||
            (place_and_time != null && !validText(place_and_time, 120, true))) {
          return res.status(400).json({ success: false, message: 'Invalid event details.' });
        }

        const newEvent = {
          id: nextId(MEMORY.events),
          event_date,
          title: title.trim(),
          place_and_time: (place_and_time || '').trim(),
          created_by: req.user.id
        };
        MEMORY.events.push(newEvent);

        if (req.app.get('io')) {
          req.app.get('io').emit('event:created', newEvent);
        }

        res.status(201).json({ success: true, message: 'Event added for this server run.', data: newEvent });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to add event.' });
      }
    });

    // DELETE /api/events/:id (Admin only)
    router.delete('/:id', verifyToken, requireAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const index = MEMORY.events.findIndex((item) => String(item.id) === String(id));
        if (index < 0) return res.status(404).json({ success: false, message: 'Event not found.' });
        MEMORY.events.splice(index, 1);

        if (req.app.get('io')) {
          req.app.get('io').emit('event:deleted', { id });
        }

        res.json({ success: true, message: 'Event deleted successfully.' });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to delete event.' });
      }
    });


    return router;
  })();
  api.use('/events', eventsRouter);

  const employeesRouter = (() => {
    const router = express.Router();
    router.param('id', validRowId);

    // GET /api/employees
    router.get('/', verifyToken, async (req, res) => {
      try {
        const { search, department, shift } = req.query;
        if ((search != null && (typeof search !== 'string' || search.length > 120)) ||
            (department != null && (typeof department !== 'string' || department.length > 80)) ||
            (shift != null && (typeof shift !== 'string' || shift.length > 30))) {
          return res.status(400).json({ success: false, message: 'Invalid employee search filters.' });
        }
        let employees = STATIC_EMPLOYEES.slice().sort((a, b) => a.name.localeCompare(b.name));
        const departments = Array.from(new Map(employees.map((employee) => employee.department.trim()).filter(Boolean).map((name) => [name.toLowerCase(), name])).values()).sort((a, b) => a.localeCompare(b));

        if (search && search.trim()) {
          const q = search.trim().toLowerCase();
          employees = employees.filter(e =>
              (e.name || '').toLowerCase().includes(q) ||
              (e.designation || '').toLowerCase().includes(q) ||
              (e.emp_id || '').toLowerCase().includes(q) ||
              (e.phone_ext || '').includes(q) ||
              (e.email || '').toLowerCase().includes(q)
          );
        }

        if (department && department !== 'All') {
          employees = employees.filter(e => (e.department || '').trim().toLowerCase() === department.trim().toLowerCase());
        }

        if (shift && shift !== 'All') {
          employees = employees.filter(e => e.shift === shift);
        }

        res.json({
          success: true,
          data: employees,
          departments
        });
      } catch (err) {
        console.error('Fetch employees error:', err);
        res.status(500).json({ success: false, message: 'Failed to retrieve employee directory.' });
      }
    });

    // GET /api/employees/departments
    router.get('/departments', verifyToken, async (req, res) => {
      try {
        const depts = Array.from(new Map(STATIC_EMPLOYEES.map((employee) => employee.department.trim()).filter(Boolean).map((name) => [name.toLowerCase(), name])).values()).sort((a, b) => a.localeCompare(b)).map((name) => ({ name }));
        res.json({ success: true, data: depts });
      } catch (err) { res.status(500).json({ success: false, message: 'Failed to fetch departments.' }); }
    });

    // POST /api/employees (Admin only)
    router.post('/', verifyToken, requireAdmin, async (req, res) => {
      try {
        const { emp_id, name, designation, department, phone_ext, shift, email } = req.body;
        const validShifts = ['General', 'Shift A', 'Shift B', 'Shift C'];
        if (!validText(emp_id, 120) ||
            !validText(name, 120) || !validText(designation, 100) ||
            !validText(department, 80) || !validText(phone_ext, 20) ||
            (shift != null && !validShifts.includes(shift)) ||
            (email != null && email !== '' && !validEmail(email))) {
          return res.status(400).json({ success: false, message: 'Invalid employee ID or employee details.' });
        }

        if (STATIC_EMPLOYEES.some((employee) => employee.emp_id === emp_id.trim())) {
          return res.status(400).json({ success: false, message: 'An employee with this Employee ID already exists.' });
        }
        const newEmp = {
          id: Math.max(0, ...STATIC_EMPLOYEES.map((employee) => Number(employee.id) || 0)) + 1,
          emp_id: emp_id.trim(),
          name: name.trim(),
          designation: designation.trim(),
          department: department.trim(),
          phone_ext: phone_ext.trim(),
          shift: shift || 'General',
          email: (email || '').trim()
        };
        STATIC_EMPLOYEES.push(newEmp);

        if (req.app.get('io')) {
          req.app.get('io').emit('employee:changed', { action: 'created', employee: newEmp });
        }

        res.status(201).json({ success: true, message: 'Added in memory for this server run; update the code data to keep it after restart.', data: newEmp });
      } catch (err) {
        console.error('Add employee error:', err);
        res.status(500).json({ success: false, message: 'Failed to add employee record.' });
      }
    });

    // PUT /api/employees/:id (Admin only)
    router.put('/:id', verifyToken, requireAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const { name, designation, department, phone_ext, shift, email } = req.body;

        const validShifts = ['General', 'Shift A', 'Shift B', 'Shift C'];
        if (!validText(name, 120) || !validText(designation, 100) ||
            !validText(department, 80) || !validText(phone_ext, 20) ||
            (shift != null && !validShifts.includes(shift)) ||
            (email != null && email !== '' && !validEmail(email))) {
          return res.status(400).json({ success: false, message: 'Invalid employee details.' });
        }

        const emp = STATIC_EMPLOYEES.find((employee) => String(employee.id) === String(id));
        if (!emp) return res.status(404).json({ success: false, message: 'Employee not found.' });
        Object.assign(emp, { name: name.trim(), designation: designation.trim(), department: department.trim(), phone_ext: phone_ext.trim(), shift: shift || 'General', email: (email || '').trim() });

        if (req.app.get('io')) {
          req.app.get('io').emit('employee:changed', { action: 'updated', employee: emp });
        }

        res.json({ success: true, message: 'Updated in memory for this server run; update the code data to keep it after restart.', data: emp });
      } catch (err) {
        console.error('Update employee error:', err);
        res.status(500).json({ success: false, message: 'Failed to update employee.' });
      }
    });

    // DELETE /api/employees/:id (Admin only)
    router.delete('/:id', verifyToken, requireAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const index = STATIC_EMPLOYEES.findIndex((employee) => String(employee.id) === String(id));
        if (index < 0) return res.status(404).json({ success: false, message: 'Employee not found.' });
        STATIC_EMPLOYEES.splice(index, 1);

        if (req.app.get('io')) {
          req.app.get('io').emit('employee:changed', { action: 'deleted', id });
        }

        res.json({ success: true, message: 'Removed in memory for this server run; update the code data to keep it after restart.' });
      } catch (err) {
        console.error('Delete employee error:', err);
        res.status(500).json({ success: false, message: 'Failed to delete employee.' });
      }
    });


    return router;
  })();
  api.use('/employees', employeesRouter);

  const documentsRouter = (() => {
    const router = express.Router();
    router.param('id', validRowId);

    // Authenticated PDF catalogue. Only filenames are returned; file paths remain server-side.
    router.get('/', verifyToken, (req, res) => {
      const search = typeof req.query.search === 'string' ? req.query.search.trim().toLowerCase() : '';
      if (req.query.search != null && (typeof req.query.search !== 'string' || req.query.search.length > 200)) {
        return res.status(400).json({ success: false, message: 'Invalid document search filter.' });
      }
      const data = PDF_DOCUMENTS
          .filter((doc) => !search || doc.name.toLowerCase().includes(search))
          .map(({ id, name }) => ({ id, name }));
      res.json({ success: true, data, total: PDF_DOCUMENTS.length });
    });

    // Serve only files from the fixed allowlist, with range support for in-browser PDF navigation.
    const streamPdf = async (req, res, document, baseDir = __dirname) => {
      if (!document || path.basename(document.name) !== document.name || !document.name.toLowerCase().endsWith('.pdf')) {
        return res.status(404).json({ success: false, message: 'PDF document not found.' });
      }

      const filePath = path.join(baseDir, document.name);
      try {
        const stats = await fs.promises.stat(filePath);
        if (!stats.isFile() || stats.size === 0) return res.status(404).json({ success: false, message: 'PDF document is unavailable.' });
      } catch (_) {
        return res.status(404).json({ success: false, message: 'PDF document is unavailable.' });
      }

      const fallbackName = document.name.replace(/[^\x20-\x7E]|["\\]/g, '_');
      const encodedName = encodeURIComponent(document.name).replace(/['()*]/g, (char) => '%' + char.charCodeAt(0).toString(16).toUpperCase());
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', 'inline; filename="' + fallbackName + '"; filename*=UTF-8\'\'' + encodedName);
      res.setHeader('Cache-Control', 'private, no-store, no-cache, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'SAMEORIGIN');
      res.setHeader('Content-Security-Policy', "frame-ancestors 'self'");
      res.sendFile(filePath, { acceptRanges: true }, (err) => {
        if (err && !res.headersSent) res.status(err.statusCode === 404 ? 404 : 500).end();
      });
    };

    // GET /api/documents/circulars - list PDFs from the existing department folders.
    // Returns only folder labels and filenames; the physical C: path stays server-side.
    router.get('/circulars', verifyToken, async (req, res) => {
      res.setHeader('Cache-Control', 'private, no-store');
      try {
        const rootStat = await fs.promises.lstat(CIRCULAR_ATTACH_ROOT);
        if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
          return res.status(503).json({ success: false, message: 'Circular documents are temporarily unavailable.' });
        }
        const currentEntries = await fs.promises.readdir(CIRCULAR_ATTACH_ROOT, { withFileTypes: true });
        const actualFolders = new Set(currentEntries.filter((entry) => entry.isDirectory() && !entry.isSymbolicLink()).map((entry) => entry.name));
        const departments = [];
        for (const department of CIRCULAR_DEPARTMENT_FOLDERS) {
          const files = [];
          if (actualFolders.has(department)) {
            const dir = path.resolve(CIRCULAR_ATTACH_ROOT, department);
            const relative = path.relative(CIRCULAR_ATTACH_ROOT, dir);
            if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) continue;
            const entries = await fs.promises.readdir(dir, { withFileTypes: true });
            for (const entry of entries) {
              const ext = path.extname(entry.name).toLowerCase();
              if (!entry.isFile() || !DEPARTMENT_DOC_TYPES[ext]) continue;
              const full = resolveDepartmentFile(CIRCULAR_ATTACH_ROOT, department + '/' + entry.name);
              if (!full) continue;
              let handle;
              try {
                handle = await fs.promises.open(full, 'r');
                const header = Buffer.alloc(8);
                const result = await handle.read(header, 0, header.length, 0);
                if (result.bytesRead !== 8 || !fileLooksLike(ext, header)) continue;
                const stats = await handle.stat();
                if (!stats.isFile() || stats.size === 0) continue;
                const displayName = entry.name.replace(/^\d{4}-\d{2}-\d{2} \d{6}(?: \(\d+\))? - /, '');
                const publishedAt = Number.isFinite(stats.birthtimeMs) && stats.birthtimeMs > 0
                  ? stats.birthtime.toISOString()
                  : stats.mtime.toISOString();
                files.push({ name: displayName, path: department + '/' + entry.name, type: ext.slice(1), modified: stats.mtime.toISOString(), publishedAt });
              } catch (err) {
                if (err && (err.code === 'EACCES' || err.code === 'EPERM')) throw err;
              } finally {
                if (handle) await handle.close().catch(() => {});
              }
            }
          }
          files.sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base', numeric: true }));
          departments.push({ name: department, files });
        }
        res.json({ success: true, departments });
      } catch (err) {
        const code = err && err.code;
        const message = code === 'EACCES' || code === 'EPERM'
          ? 'The server is not allowed to read the Circulars folders.'
          : 'Circular documents are temporarily unavailable.';
        return res.status(503).json({ success: false, code, message });
      }
    });

    // GET /api/documents/department/:dept - files in that department's folder of the share.
    router.get('/department/:dept', verifyToken, async (req, res) => {
      const dir = departmentDir(req.params.dept);
      if (dir == null) return res.status(404).json({ success: false, message: 'Unknown department.' });
      res.setHeader('Cache-Control', 'no-store');
      const cached = departmentDocCache.get(req.params.dept);
      if (cached && Date.now() - cached.at < DEPARTMENT_DOC_CACHE_MS && req.query.refresh == null) return res.json(cached.body);
      const data = [];
      try {
        await listDepartmentFiles(dir, [], 0, data);
      } catch (err) {
        const code = err && err.code ? String(err.code) : 'ERROR';
        console.error('Department documents (' + req.params.dept + '):', code, err && err.message);
        const reason = code === 'ENOENT' ? 'The folder was not found.' : (code === 'EACCES' || code === 'EPERM') ? 'Access to the folder was denied.' : 'The shared folder could not be reached.';
        return res.status(503).json({ success: false, code, message: reason });
      }
      data.sort((a, b) => a.folder.localeCompare(b.folder, undefined, { sensitivity: 'base', numeric: true }) || a.name.localeCompare(b.name, undefined, { sensitivity: 'base', numeric: true }));
      const body = { success: true, data, total: data.length, truncated: data.length >= DEPARTMENT_DOC_MAX_FILES };
      departmentDocCache.set(req.params.dept, { at: Date.now(), body });
      res.json(body);
    });

    // GET /api/documents/circular-file?p=Quality/2026-11-18 101500 - QC-14.pdf[&download=1]
    // Opens a circular attachment from the Circulars folder only.
    router.get('/circular-file', verifyToken, async (req, res) => {
      const requestedPath = typeof req.query.p === 'string' ? req.query.p : '';
      const parts = requestedPath.split('/');
      const allowedFolder = parts.length === 2 && CIRCULAR_DEPARTMENT_FOLDERS.includes(parts[0]);
      const full = allowedFolder ? resolveDepartmentFile(CIRCULAR_ATTACH_ROOT, requestedPath) : null;
      if (!full) return res.status(404).json({ success: false, message: 'Attachment not found.' });
      try {
        const [folderStat, fileStat] = await Promise.all([
          fs.promises.lstat(path.join(CIRCULAR_ATTACH_ROOT, parts[0])),
          fs.promises.lstat(full)
        ]);
        if (!folderStat.isDirectory() || folderStat.isSymbolicLink() || !fileStat.isFile() || fileStat.isSymbolicLink()) {
          return res.status(404).json({ success: false, message: 'Attachment not found.' });
        }
      } catch (_) { return res.status(404).json({ success: false, message: 'Attachment not found.' }); }
      const ext = path.extname(full).toLowerCase();
      if (ext === '.pdf' && req.query.download == null) return streamPdf(req, res, { name: path.basename(full) }, path.dirname(full));
      const name = path.basename(full).replace(/^\d{4}-\d{2}-\d{2} \d{6}(?: \(\d+\))? - /, '');
      const fallbackName = name.replace(/[^\x20-\x7E]|["\\]/g, '_');
      const encodedName = encodeURIComponent(name).replace(/['()*]/g, (char) => '%' + char.charCodeAt(0).toString(16).toUpperCase());
      res.setHeader('Content-Type', DEPARTMENT_DOC_TYPES[ext]);
      const inlineImage = req.query.view === '1' && req.query.download == null && ['.jpg', '.jpeg', '.png'].includes(ext);
      res.setHeader('Content-Disposition', (inlineImage ? 'inline' : 'attachment') + '; filename="' + fallbackName + '"; filename*=UTF-8\'\'' + encodedName);
      res.setHeader('Cache-Control', 'private, no-store');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.sendFile(full, (err) => {
        if (err && !res.headersSent) res.status(err.statusCode === 404 || err.code === 'ENOENT' ? 404 : 500).json({ success: false, message: 'Attachment is unavailable.' });
      });
    });

    // GET /api/documents/department/:dept/open?p=Folder/File.pdf[&download=1]
    // Streams one file from inside that department's folder only.
    router.get('/department/:dept/open', verifyToken, (req, res) => {
      const dir = departmentDir(req.params.dept);
      const full = dir == null || typeof req.query.p !== 'string' ? null : resolveDepartmentFile(dir, req.query.p);
      if (!full) return res.status(404).json({ success: false, message: 'Document not found.' });
      const ext = path.extname(full).toLowerCase();
      if (ext === '.pdf' && req.query.download == null) {
        return streamPdf(req, res, { name: path.basename(full) }, path.dirname(full));
      }
      const name = path.basename(full);
      const fallbackName = name.replace(/[^\x20-\x7E]|["\\]/g, '_');
      const encodedName = encodeURIComponent(name).replace(/['()*]/g, (char) => '%' + char.charCodeAt(0).toString(16).toUpperCase());
      res.setHeader('Content-Type', DEPARTMENT_DOC_TYPES[ext]);
      res.setHeader('Content-Disposition', 'attachment; filename="' + fallbackName + '"; filename*=UTF-8\'\'' + encodedName);
      res.setHeader('Cache-Control', 'private, no-store');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.sendFile(full, (err) => {
        if (err && !res.headersSent) res.status(err.statusCode === 404 || err.code === 'ENOENT' ? 404 : 500).json({ success: false, message: 'Document is unavailable.' });
      });
    });

    // IIS rewrites direct root-level .pdf requests here, so IIS never serves these files statically.
    router.get('/file/:name', verifyToken, (req, res) => {
      const document = PDF_DOCUMENTS.find((entry) => entry.name === req.params.name);
      return streamPdf(req, res, document);
    });

    router.get('/:id/pdf', verifyToken, (req, res) => {
      const document = PDF_DOCUMENTS.find((entry) => String(entry.id) === req.params.id);
      return streamPdf(req, res, document);
    });

    return router;
  })();
  api.use('/documents', documentsRouter);

  // GET /api/employee-details. Columns up to Voter ID, Aadhaar masked to the last 4 digits.
  const employeeDetailsRouter = express.Router();
  employeeDetailsRouter.get('/', verifyToken, (req, res) => {
    const data = EMPLOYEE_DETAILS_SOURCE.map((row) => EMPLOYEE_DETAILS_DISPLAY_INDEXES.map((sourceIndex, position) => (position === EMPLOYEE_DETAILS_AADHAAR_POSITION ? maskAadhaar(row[sourceIndex]) : row[sourceIndex])));
    res.setHeader('Cache-Control', 'no-store');
    res.json({
      success: true,
      total: data.length,
      columns: EMPLOYEE_DETAILS_DISPLAY_COLUMNS,
      canViewSensitive: true,
      data
    });
  });
  api.use('/employee-details', employeeDetailsRouter);

  // GET /api/assets (Authenticated inventory)
  const assetsRouter = express.Router();
  assetsRouter.get('/', verifyToken, requireAdmin, (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.json({ success: true, columns: ASSET_COLUMNS, data: STATIC_ASSETS });
  });
  // PATCH /api/assets/:index/assignment (Admin-only User Id / Name editing)
  assetsRouter.patch('/:index/assignment', verifyToken, requireAdmin, (req, res) => {
    const indexText = req.params.index;
    const index = Number(indexText);
    const allowedFields = new Set(['User Id', 'Name']);
    if (!/^\d+$/.test(indexText) || !Number.isSafeInteger(index) || index < 0 || index >= STATIC_ASSETS.length) {
      return res.status(404).json({ success: false, message: 'Asset record not found.' });
    }
    if (Object.keys(req.body).some((key) => !allowedFields.has(key)) ||
        !validText(req.body['User Id'], 100, true) || !validText(req.body.Name, 120, true)) {
      return res.status(400).json({ success: false, message: 'Only valid User Id and Name values can be updated.' });
    }
    const asset = STATIC_ASSETS[index];
    asset['User Id'] = req.body['User Id'].trim();
    asset.Name = req.body.Name.trim();
    res.json({ success: true, message: 'Asset assignment updated for this server run.', data: asset });
  });
  api.use('/assets', assetsRouter);

  // Inter-Com directory uses code-managed data; only Admin may change records.
  const intercomDetailsRouter = express.Router();
  intercomDetailsRouter.param('id', validRowId);
  const validIntercomInput = (body) => {
    if (!body || typeof body !== 'object' || Array.isArray(body) ||
        Object.keys(body).some((key) => !['department', 'name', 'extension'].includes(key))) return false;
    const extension = typeof body.extension === 'number' ? String(body.extension) : body.extension;
    return validText(body.department, 120) && validText(body.name, 180, true) &&
      typeof extension === 'string' && /^\d{1,10}$/.test(extension);
  };
  intercomDetailsRouter.get('/', verifyToken, (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.json({ success: true, columns: INTERCOM_DETAILS_COLUMNS, total: MEMORY.intercomDetails.length, data: MEMORY.intercomDetails.map((row) => ({ ...row })) });
  });
  intercomDetailsRouter.post('/', verifyToken, requireAdmin, (req, res) => {
    const body = req.body || {};
    if (!validIntercomInput(body)) return res.status(400).json({ success: false, message: 'Enter a valid department, name, and numeric extension.' });
    const extension = Number(body.extension);
    const serial = MEMORY.intercomDetails.reduce((max, row) => Math.max(max, Number(row['S.No']) || 0), 0) + 1;
    const item = { id: nextId(MEMORY.intercomDetails), 'S.No': serial, Department: body.department.trim(), Name: body.name.trim(), 'Tel.No': extension };
    MEMORY.intercomDetails.push(item);
    if (req.app.get('io')) req.app.get('io').emit('intercom:changed', { action: 'created', id: item.id });
    res.status(201).json({ success: true, data: item, message: 'Inter-Com entry added for this server run.' });
  });
  intercomDetailsRouter.put('/:id', verifyToken, requireAdmin, (req, res) => {
    const item = MEMORY.intercomDetails.find((row) => String(row.id) === String(req.params.id));
    if (!item) return res.status(404).json({ success: false, message: 'Inter-Com entry not found.' });
    const body = req.body || {};
    if (!validIntercomInput(body)) return res.status(400).json({ success: false, message: 'Enter a valid department, name, and numeric extension.' });
    item.Department = body.department.trim();
    item.Name = body.name.trim();
    item['Tel.No'] = Number(body.extension);
    if (req.app.get('io')) req.app.get('io').emit('intercom:changed', { action: 'updated', id: item.id });
    res.json({ success: true, data: item, message: 'Inter-Com entry updated for this server run.' });
  });
  intercomDetailsRouter.delete('/:id', verifyToken, requireAdmin, (req, res) => {
    const index = MEMORY.intercomDetails.findIndex((row) => String(row.id) === String(req.params.id));
    if (index < 0) return res.status(404).json({ success: false, message: 'Inter-Com entry not found.' });
    const [item] = MEMORY.intercomDetails.splice(index, 1);
    if (req.app.get('io')) req.app.get('io').emit('intercom:changed', { action: 'deleted', id: item.id });
    res.json({ success: true, message: 'Inter-Com entry removed for this server run.' });
  });
  api.use('/intercom-details', intercomDetailsRouter);

  // IT incident tickets carry contact and remote-support details. Only admins (IT) see
  // them; everyone else sees the ticket without those fields.
  const TICKET_PRIVATE_FIELDS = ['emp_code', 'contact_no', 'alt_contact', 'remote_tool', 'remote_id', 'computer_name'];
  const TICKET_ISSUE_TYPES = ['Computer / laptop', 'Printer / scanner', 'Network / internet', 'E-mail / Microsoft 365', 'SAP', 'MES / other software', 'Login / password', 'CCTV / biometric', 'New software or access', 'Other'];
  const TICKET_REMOTE_TOOLS = ['UltraViewer', 'AnyDesk', 'Quick Assist', 'TeamViewer', 'Other'];
  const publicTicket = (ticket, user) => {
    if (user && user.role === 'admin') return ticket;
    const copy = { ...ticket };
    for (const field of TICKET_PRIVATE_FIELDS) delete copy[field];
    return copy;
  };
  const optionalMatch = (value, pattern) => value == null || value === '' || (typeof value === 'string' && pattern.test(value.trim()));

  const helpdeskRouter = (() => {
    const router = express.Router();
    router.param('id', validRowId);

    // GET /api/helpdesk
    router.get('/', verifyToken, async (req, res) => {
      try {
        const { mine, status } = req.query;
        let tickets = MEMORY.tickets.slice().sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));

        if (mine === 'true') {
          tickets = tickets.filter(t => t.submitted_by === req.user.id);
        }

        if (status && status !== 'All') {
          tickets = tickets.filter(t => t.status === status);
        }

        res.json({ success: true, data: tickets.map((t) => publicTicket(t, req.user)) });
      } catch (err) {
        console.error('Fetch helpdesk error:', err);
        res.status(500).json({ success: false, message: 'Failed to retrieve helpdesk tickets.' });
      }
    });

    // POST /api/helpdesk (Employees & Admins)
    router.post('/', verifyToken, async (req, res) => {
      try {
        const { kind, priority, title, machine_or_location, detail, requester_name,
                emp_code, from_dept, contact_no, alt_contact, issue_type, remote_tool, remote_id, computer_name } = req.body;
        const validKinds = ['Maintenance', 'IT', 'Stores', 'Safety hazard', 'Other'];
        if (!validText(title, 160) ||
            (kind != null && !validKinds.includes(kind)) ||
            (priority != null && !['Normal', 'Urgent'].includes(priority)) ||
            (machine_or_location != null && !validText(machine_or_location, 100, true)) ||
            (detail != null && !validText(detail, 10000, true)) ||
            (requester_name != null && !validText(requester_name, 80, true)) ||
            !optionalMatch(emp_code, /^[A-Za-z0-9\-\/]{1,20}$/) ||
            (from_dept != null && !validText(from_dept, 80, true)) ||
            !optionalMatch(contact_no, /^[0-9+()\-\s]{3,20}$/) ||
            !optionalMatch(alt_contact, /^[0-9+()\-\s]{3,20}$/) ||
            (issue_type != null && issue_type !== '' && !TICKET_ISSUE_TYPES.includes(issue_type)) ||
            (remote_tool != null && remote_tool !== '' && !TICKET_REMOTE_TOOLS.includes(remote_tool)) ||
            !optionalMatch(remote_id, /^[A-Za-z0-9@.\-\s]{1,40}$/) ||
            (computer_name != null && !validText(computer_name, 60, true))) {
          return res.status(400).json({ success: false, message: 'Invalid helpdesk request details.' });
        }
        // An IT incident needs enough detail for IT to call back and connect.
        if ((kind || 'Maintenance') === 'IT' &&
            (!String(requester_name || '').trim() || !String(emp_code || '').trim() || !String(from_dept || '').trim() ||
             !String(contact_no || '').trim() || !issue_type)) {
          return res.status(400).json({ success: false, message: 'For an IT incident, give your name, employee code, department, contact number and the type of issue.' });
        }
        const clean = (value) => String(value == null ? '' : value).trim().replace(/\s+/g, ' ');

        const ticket_ref = 'T-' + crypto.randomBytes(4).toString('hex').toUpperCase();
        const k = kind || 'Maintenance';
        const prio = priority || 'Normal';
        const loc = (machine_or_location || '').trim();
        const det = (detail || '').trim();

        const newTicket = {
          id: nextId(MEMORY.tickets),
          ticket_ref,
          kind: k,
          priority: prio,
          title: title.trim(),
          machine_or_location: loc,
          detail: det,
          status: 'Open',
          submitted_by: req.user.id,
          submitter_name: (requester_name || '').trim() || req.user.full_name,
          from_dept: clean(from_dept),
          issue_type: clean(issue_type),
          emp_code: clean(emp_code).toUpperCase(),
          contact_no: clean(contact_no),
          alt_contact: clean(alt_contact),
          remote_tool: clean(remote_tool),
          remote_id: clean(remote_id),
          computer_name: clean(computer_name),
          created_at: new Date().toISOString()
        };
        MEMORY.tickets.push(newTicket);

        if (req.app.get('io')) {
          req.app.get('io').emit('ticket:created', publicTicket(newTicket, null));
        }

        res.status(201).json({ success: true, message: 'Helpdesk request registered.', data: publicTicket(newTicket, req.user) });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to create helpdesk ticket.' });
      }
    });

    // PATCH /api/helpdesk/:id/status (Admin only)
    router.patch('/:id/status', verifyToken, requireAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const { status } = req.body;

        const validStatuses = ['Open', 'In progress', 'Done'];
        if (!validStatuses.includes(status)) {
          return res.status(400).json({ success: false, message: 'Invalid status. Must be Open, In progress, or Done.' });
        }

        const ticket = MEMORY.tickets.find((item) => String(item.id) === String(id));
        if (!ticket) return res.status(404).json({ success: false, message: 'Ticket not found.' });
        ticket.status = status;

        if (req.app.get('io')) {
          req.app.get('io').emit('ticket:status_changed', { id, status });
        }

        res.json({ success: true, message: 'Ticket status updated to ' + status });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to update ticket status.' });
      }
    });

    // DELETE /api/helpdesk/:id (Admin only)
    router.delete('/:id', verifyToken, requireAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const index = MEMORY.tickets.findIndex((item) => String(item.id) === String(id));
        if (index < 0) return res.status(404).json({ success: false, message: 'Ticket not found.' });
        MEMORY.tickets.splice(index, 1);

        if (req.app.get('io')) {
          req.app.get('io').emit('ticket:deleted', { id });
        }

        res.json({ success: true, message: 'Helpdesk ticket deleted.' });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to delete ticket.' });
      }
    });


    return router;
  })();
  api.use('/helpdesk', helpdeskRouter);

  // ---------------------------------------------------------------------------
  // Biometric attendance summary from eTimeTrack (read-only).
  // The server signs in to the eTimeTrack web dashboard with a view-only account,
  // reads the five dashboard figures and returns them. It only loads pages and
  // submits the sign-in form; it never clicks anything else, so no record in
  // eTimeTrack can be changed. Settings in .env:
  //   ETIME_URL=http://time.microtechcnc.in:9002/Main.aspx
  //   ETIME_USER=viewonly-user        ETIME_PASSWORD=its-password
  // ---------------------------------------------------------------------------
  const ETIME_URL = (process.env.ETIME_URL || 'http://time.microtechcnc.in:9002/Main.aspx').trim();
  const ETIME_USER = (process.env.ETIME_USER || '').trim();
  const ETIME_PASSWORD = process.env.ETIME_PASSWORD || '';
  const ETIME_CACHE_MS = 30000;   // same as eTimeTrack's own 30-second auto refresh
  const ETIME_TIMEOUT_MS = 15000;
  const ETIME_FIGURES = {
    registered: 'Registered Employees',
    active: 'Active Employees',
    present: 'Present Employees',
    online: 'Online Devices',
    offline: 'Offline Devices'
  };
  let etimeCache = null;
  let etimeInflight = null;

  const htmlDecode = (text) => String(text)
    .replace(/&nbsp;/gi, ' ').replace(/&amp;/gi, '&').replace(/&lt;/gi, '<').replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'")
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCharCode(parseInt(n, 16)));
  const pageText = (html) => htmlDecode(String(html)
    .replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim();
  const tagAttrs = (tag) => {
    const attrs = {};
    const re = /([a-zA-Z_:][-\w:.]*)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
    let m; const body = tag.replace(/^<\s*\w+/, '').replace(/\/?>$/, '');
    while ((m = re.exec(body))) attrs[m[1].toLowerCase()] = htmlDecode(m[2] ?? m[3] ?? m[4] ?? '');
    return attrs;
  };
  const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  function readFigures(html) {
    const text = pageText(html);
    const out = {};
    for (const [key, label] of Object.entries(ETIME_FIGURES)) {
      const words = escapeRe(label).replace(/\s+/g, '\\s*');
      const before = new RegExp('(\\d[\\d,]*)\\s*' + words, 'i').exec(text);
      const after = new RegExp(words + '\\s*:?\\s*(\\d[\\d,]*)', 'i').exec(text);
      const m = before || after;
      if (m) out[key] = Number(m[1].replace(/,/g, ''));
    }
    return out;
  }

  // Reads the device status table (DeviceSName, DeviceFName, Serial No., Location,
  // Last Ping, Status) from the dashboard page. Rows are recognised by an
  // online/offline status cell; header names decide which cell is which.
  const cellText = (html) => pageText(html);
  function readDevices(html) {
    const clean = String(html).replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<style[\s\S]*?<\/style>/gi, ' ');
    const want = { short: /^device\s*s\s*name$/i, full: /^device\s*f\s*name$/i, serial: /^serial/i, location: /^location$/i, last_ping: /^last\s*ping$/i, status: /^status$/i };
    let map = null;
    const devices = [];
    for (const row of clean.matchAll(/<tr\b[^>]*>([\s\S]*?)<\/tr>/gi)) {
      const cells = [...row[1].matchAll(/<t([dh])\b[^>]*>([\s\S]*?)<\/t\1>/gi)].map((c) => cellText(c[2]));
      if (cells.length < 4) continue;
      if (cells.some((c) => want.short.test(c)) && cells.some((c) => want.status.test(c))) {
        map = {};
        cells.forEach((c, i) => { for (const [k, re] of Object.entries(want)) if (!(k in map) && re.test(c)) map[k] = i; });
        continue;
      }
      const statusAt = cells.findIndex((c) => /^(online|offline)$/i.test(c));
      if (statusAt === -1) continue;
      const pick = (k, fallback) => cells[map && map[k] != null ? map[k] : fallback] || '';
      const device = {
        short: pick('short', 0), full: pick('full', 1), serial: pick('serial', 2),
        location: pick('location', 3), last_ping: pick('last_ping', 4),
        status: pick('status', statusAt).toLowerCase() === 'online' ? 'online' : 'offline'
      };
      if (device.short && !devices.some((d) => d.serial === device.serial && d.short === device.short)) devices.push(device);
      if (devices.length >= 500) break;
    }
    return devices;
  }

  async function etimeSession() {
    const jar = new Map();
    const cookieHeader = () => [...jar].map(([k, v]) => k + '=' + v).join('; ');
    const keepCookies = (res) => {
      const list = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
      for (const c of list) { const m = /^\s*([^=;]+)=([^;]*)/.exec(c); if (m) jar.set(m[1].trim(), m[2]); }
    };
    // Loads a page, following redirects by hand so session cookies are kept.
    async function request(url, method = 'GET', form = null) {
      let current = new URL(url, ETIME_URL).href;
      for (let hop = 0; hop < 6; hop++) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), ETIME_TIMEOUT_MS);
        let res;
        try {
          res = await fetch(current, {
            method, redirect: 'manual', signal: controller.signal,
            headers: Object.assign({ 'User-Agent': 'MTCNC-Intranet/1.0 (read-only dashboard)', Cookie: cookieHeader() },
              form ? { 'Content-Type': 'application/x-www-form-urlencoded' } : {}),
            body: form ? new URLSearchParams(form).toString() : undefined
          });
        } finally { clearTimeout(timer); }
        keepCookies(res);
        if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
          current = new URL(res.headers.get('location'), current).href;
          method = 'GET'; form = null;
          continue;
        }
        return { url: current, status: res.status, html: await res.text() };
      }
      throw new Error('Too many redirects from eTimeTrack.');
    }
    return { request };
  }

  // Fills in the sign-in form found on the page (works with ASP.NET WebForms pages).
  function buildLoginForm(page) {
    const formMatch = /<form\b[^>]*>[\s\S]*?<\/form>/i.exec(page.html);
    const formHtml = formMatch ? formMatch[0] : page.html;
    const formTag = /<form\b[^>]*>/i.exec(formHtml);
    const action = new URL((formTag && tagAttrs(formTag[0]).action) || page.url, page.url).href;
    const fields = {};
    let userField = null; let passField = null; let submit = null;
    for (const m of formHtml.matchAll(/<input\b[^>]*>/gi)) {
      const a = tagAttrs(m[0]);
      const type = (a.type || 'text').toLowerCase();
      if (!a.name) continue;
      if (type === 'hidden') fields[a.name] = a.value || '';
      else if (type === 'password' && !passField) passField = a.name;
      else if ((type === 'text' || type === 'email') && !userField) userField = a.name;
      else if ((type === 'submit' || type === 'image') && !submit) submit = a;
      else if ((type === 'checkbox' || type === 'radio') && 'checked' in a) fields[a.name] = a.value || 'on';
    }
    for (const m of formHtml.matchAll(/<select\b[^>]*name\s*=\s*["']?([^"'\s>]+)[^>]*>([\s\S]*?)<\/select>/gi)) {
      const selected = /<option\b[^>]*selected[^>]*>/i.exec(m[2]) || /<option\b[^>]*>/i.exec(m[2]);
      if (selected) fields[m[1]] = tagAttrs(selected[0]).value || '';
    }
    if (!userField || !passField) return null;
    fields[userField] = ETIME_USER;
    fields[passField] = ETIME_PASSWORD;
    if (submit) {
      if ((submit.type || '').toLowerCase() === 'image') { fields[submit.name + '.x'] = '10'; fields[submit.name + '.y'] = '10'; }
      else fields[submit.name] = submit.value || 'Login';
    } else {
      // Link-style button: javascript:__doPostBack('ctl00$btnLogin','')
      const pb = /__doPostBack\(\s*['"]([^'"]+)['"]/i.exec(formHtml);
      if (pb && '__EVENTTARGET' in fields) fields.__EVENTTARGET = pb[1];
    }
    return { action, fields };
  }

  async function fetchEtimeSummary() {
    if (!ETIME_USER || !ETIME_PASSWORD) {
      const err = new Error('eTimeTrack sign-in is not set up yet. Add ETIME_USER and ETIME_PASSWORD to .env on the server.');
      err.code = 'NOT_CONFIGURED'; throw err;
    }
    const { request } = await etimeSession();
    let page = await request(ETIME_URL);
    const isLogin = (p) => /<input\b[^>]*type\s*=\s*["']?password/i.test(p.html);
    if (isLogin(page)) {
      const login = buildLoginForm(page);
      if (!login) { const err = new Error('The eTimeTrack sign-in form could not be read.'); err.code = 'LOGIN_FORM'; throw err; }
      page = await request(login.action, 'POST', login.fields);
      if (isLogin(page)) { const err = new Error('eTimeTrack did not accept the user name or password in .env.'); err.code = 'LOGIN_FAILED'; throw err; }
      if (new URL(page.url).pathname.toLowerCase() !== new URL(ETIME_URL).pathname.toLowerCase()) page = await request(ETIME_URL);
    }
    // Keep a copy of the last dashboard page read (no password is in it) so IT can
    // check what the server sees: logs\etime-last-page.html
    try {
      const dir = path.join(__dirname, 'logs');
      await fs.promises.mkdir(dir, { recursive: true });
      await fs.promises.writeFile(path.join(dir, 'etime-last-page.html'), '<!-- read ' + new Date().toISOString() + ' from ' + page.url + ' (HTTP ' + page.status + ') -->\n' + page.html, 'utf8');
    } catch (_) { /* copy is optional */ }
    if (page.status >= 400) { const err = new Error('eTimeTrack answered with HTTP ' + page.status + '.'); err.code = 'HTTP_' + page.status; throw err; }
    const figures = readFigures(page.html);
    const devices = readDevices(page.html);
    if (!['active', 'present', 'online', 'offline'].some((k) => k in figures) && !devices.length) {
      const err = new Error('The dashboard figures were not found on the eTimeTrack page.');
      err.code = 'NO_FIGURES';
      err.hint = pageText(page.html).slice(0, 300);
      throw err;
    }
    return { figures, devices };
  }

  const attendanceRouter = express.Router();
  // GET /api/attendance/summary - figures and device list, cached for 30 seconds so eTimeTrack is not loaded by every viewer.
  attendanceRouter.get('/summary', verifyToken, async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    const admin = req.user && req.user.role === 'admin';
    if (etimeCache && Date.now() - etimeCache.at < ETIME_CACHE_MS) {
      return res.json({ success: true, data: etimeCache.data, devices: etimeCache.devices, fetched_at: etimeCache.fetched_at, source: 'eTimeTrack' });
    }
    try {
      if (!etimeInflight) etimeInflight = fetchEtimeSummary().finally(() => { etimeInflight = null; });
      const result = await etimeInflight;
      etimeCache = { at: Date.now(), data: result.figures, devices: result.devices, fetched_at: new Date().toISOString() };
      res.json({ success: true, data: etimeCache.data, devices: etimeCache.devices, fetched_at: etimeCache.fetched_at, source: 'eTimeTrack' });
    } catch (err) {
      const code = err.code || (err.name === 'AbortError' ? 'TIMEOUT' : (err.cause && err.cause.code) || 'ERROR');
      console.error('eTimeTrack summary:', code, err.message);
      const message = code === 'TIMEOUT' ? 'eTimeTrack did not answer in time.'
        : /^(ENOTFOUND|ECONNREFUSED|EHOSTUNREACH|ETIMEDOUT|ECONNRESET|UND_ERR)/.test(code) ? 'The eTimeTrack server could not be reached.'
        : err.message;
      const body = { success: false, code, message };
      if (admin && err.hint) body.hint = err.hint;
      // Serve the last good figures (marked stale) rather than nothing.
      if (etimeCache) Object.assign(body, { stale: true, data: etimeCache.data, devices: etimeCache.devices, fetched_at: etimeCache.fetched_at });
      res.status(503).json(body);
    }
  });
  api.use('/attendance', attendanceRouter);


  const suggestionsRouter = (() => {
    const router = express.Router();
    router.param('id', validRowId);

    // GET /api/suggestions
    router.get('/', verifyToken, async (req, res) => {
      try {
        const isAdmin = req.user.role === 'admin';
        let suggestions = MEMORY.suggestions.slice().sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));

        if (!isAdmin) {
          // Everyone shares the employee session, so employees only get the ideas
          // whose ids their own browser remembers (?ids=1,2,3).
          const ids = new Set(String(req.query.ids || '').split(',').filter((v) => /^\d{1,10}$/.test(v)).map(Number));
          suggestions = suggestions.filter(s => ids.has(Number(s.id)));
        }

        const formatted = suggestions.map(s => ({
          ...s,
          submitter_name: s.submitter_name || (s.submitted_by === req.user.id ? `${req.user.full_name} (you)` : 'Colleague')
        }));

        res.json({ success: true, data: formatted });
      } catch (err) {
        console.error('Fetch suggestions error:', err);
        res.status(500).json({ success: false, message: 'Failed to retrieve suggestions.' });
      }
    });

    // POST /api/suggestions
    router.post('/', verifyToken, async (req, res) => {
      try {
        const { category, suggestion_text, requester_name } = req.body;
        const categories = ['Safety', 'Process improvement', 'Workplace', 'Other'];
        if (!validText(suggestion_text, 10000) ||
            (category != null && !categories.includes(category)) ||
            (requester_name != null && !validText(requester_name, 80, true))) {
          return res.status(400).json({ success: false, message: 'Invalid suggestion details.' });
        }

        const cat = category || 'General';
        const text = suggestion_text.trim();

        const newSuggestion = {
          id: nextId(MEMORY.suggestions),
          category: cat,
          suggestion_text: text,
          submitted_by: req.user.id,
          submitter_name: (requester_name || '').trim() || 'Anonymous',
          created_at: new Date().toISOString()
        };
        MEMORY.suggestions.push(newSuggestion);

        if (req.app.get('io')) {
          const io = req.app.get('io');
          io.to('admins').emit('suggestion:created', newSuggestion);
        }

        res.status(201).json({ success: true, message: 'Thank you! Your idea has been sent to plant management for this server run.', data: newSuggestion });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to submit suggestion.' });
      }
    });

    // DELETE /api/suggestions/:id (Admin only)
    router.delete('/:id', verifyToken, requireAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const index = MEMORY.suggestions.findIndex((item) => String(item.id) === String(id));
        if (index < 0) return res.status(404).json({ success: false, message: 'Suggestion not found.' });
        MEMORY.suggestions.splice(index, 1);

        if (req.app.get('io')) {
          req.app.get('io').to('admins').emit('suggestion:deleted', { id });
        }

        res.json({ success: true, message: 'Suggestion removed.' });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to delete suggestion.' });
      }
    });


    return router;
  })();
  api.use('/suggestions', suggestionsRouter);

  const hrRouter = (() => {
    const router = express.Router();
    router.param('id', validRowId);
    const validContactEmails = (value) => validText(value, 120, true) &&
      value.split(/[;,]/).map((item) => item.trim()).filter(Boolean).every((item) => validEmail(item));

    // GET /api/hr
    router.get('/', verifyToken, async (req, res) => {
      try {
        const hrDocs = HR_STATIC_DOCUMENTS;
        const hrPeople = MEMORY.hrContacts.slice();
        const holidays = MEMORY.holidays.slice();

        res.json({
          success: true,
          data: {
            documents: hrDocs,
            contacts: hrPeople,
            holidays: holidays || []
          }
        });
      } catch (err) {
        console.error('Fetch HR data error:', err);
        res.status(500).json({ success: false, message: 'Failed to retrieve HR and holiday information.' });
      }
    });

    // Fixed, authenticated PDF route for the 2026 holiday list. The filename is
    // server-side and never accepted from request input.
    router.get('/policy-pdf', verifyToken, async (req, res) => {
      const fileName = 'List of Holiday for 2026.pdf';
      const filePath = path.resolve(__dirname, fileName);
      if (path.dirname(filePath) !== __dirname || path.basename(filePath) !== fileName) {
        return res.status(404).json({ success: false, message: 'HR document is unavailable.' });
      }
      try {
        const stat = await fs.promises.stat(filePath);
        if (!stat.isFile() || stat.size === 0) return res.status(404).json({ success: false, message: 'HR document is unavailable.' });
      } catch (_) {
        return res.status(404).json({ success: false, message: 'HR document is unavailable.' });
      }
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', 'inline; filename="List of Holiday for 2026.pdf"');
      res.setHeader('Cache-Control', 'private, no-store, no-cache, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'SAMEORIGIN');
      res.setHeader('Content-Security-Policy', "frame-ancestors 'self'");
      res.sendFile(filePath, { acceptRanges: true }, (err) => {
        if (err && !res.headersSent) res.status(err.statusCode === 404 ? 404 : 500).end();
      });
    });

    // HR contacts are kept in the existing in-memory data store; only Admin may change them.
    router.post('/contacts', verifyToken, requireAdmin, async (req, res) => {
      try {
        const { name, department = '', phone_ext = '', email = '' } = req.body || {};
        if (!validText(name, 120) || !validText(department, 80, true) || !validText(phone_ext, 100, true) || !validContactEmails(email)) {
          return res.status(400).json({ success: false, message: 'Enter a valid contact name, department, phone or extension, and e-mail.' });
        }
        const contact = {
          id: nextId(MEMORY.hrContacts), name: name.trim(), department: department.trim(),
          phone_ext: phone_ext.trim(), email: email.trim()
        };
        MEMORY.hrContacts.push(contact);
        if (req.app.get('io')) req.app.get('io').emit('hr-contact:changed', { action: 'created', id: contact.id });
        res.status(201).json({ success: true, data: contact });
      } catch (_) {
        res.status(500).json({ success: false, message: 'Failed to create HR contact.' });
      }
    });

    router.put('/contacts/:id', verifyToken, requireAdmin, async (req, res) => {
      try {
        const contact = MEMORY.hrContacts.find((item) => String(item.id) === String(req.params.id));
        if (!contact) return res.status(404).json({ success: false, message: 'HR contact not found.' });
        const { name, department = '', phone_ext = '', email = '' } = req.body || {};
        if (!validText(name, 120) || !validText(department, 80, true) || !validText(phone_ext, 100, true) || !validContactEmails(email)) {
          return res.status(400).json({ success: false, message: 'Enter a valid contact name, department, phone or extension, and e-mail.' });
        }
        Object.assign(contact, { name: name.trim(), department: department.trim(), phone_ext: phone_ext.trim(), email: email.trim() });
        if (req.app.get('io')) req.app.get('io').emit('hr-contact:changed', { action: 'updated', id: contact.id });
        res.json({ success: true, data: contact });
      } catch (_) {
        res.status(500).json({ success: false, message: 'Failed to update HR contact.' });
      }
    });

    router.delete('/contacts/:id', verifyToken, requireAdmin, async (req, res) => {
      try {
        const index = MEMORY.hrContacts.findIndex((item) => String(item.id) === String(req.params.id));
        if (index < 0) return res.status(404).json({ success: false, message: 'HR contact not found.' });
        const [contact] = MEMORY.hrContacts.splice(index, 1);
        if (req.app.get('io')) req.app.get('io').emit('hr-contact:changed', { action: 'deleted', id: contact.id });
        res.json({ success: true, message: 'HR contact removed.' });
      } catch (_) {
        res.status(500).json({ success: false, message: 'Failed to delete HR contact.' });
      }
    });

    // POST /api/hr/holidays (Admin only)
    router.post('/holidays', verifyToken, requireAdmin, async (req, res) => {
      try {
        const { holiday_date, name, day_name } = req.body;
        if (!validIsoDate(holiday_date) || !validText(name, 100)) {
          return res.status(400).json({ success: false, message: 'Invalid holiday details.' });
        }

        const d = new Date(holiday_date + 'T00:00:00');
        const calculatedDay = d.toLocaleDateString('en-US', { weekday: 'long' });

        const newHoliday = {
          id: nextId(MEMORY.holidays),
          holiday_date,
          name: name.trim(),
          day_name: calculatedDay
        };
        MEMORY.holidays.push(newHoliday);

        if (req.app.get('io')) {
          req.app.get('io').emit('holiday:changed', { action: 'created', holiday: newHoliday });
        }

        res.status(201).json({ success: true, message: 'Holiday added for this server run.', data: newHoliday });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to add holiday.' });
      }
    });

    // DELETE /api/hr/holidays/:id (Admin only)
    router.delete('/holidays/:id', verifyToken, requireAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const index = MEMORY.holidays.findIndex((item) => String(item.id) === String(id));
        if (index < 0) return res.status(404).json({ success: false, message: 'Holiday not found.' });
        MEMORY.holidays.splice(index, 1);

        if (req.app.get('io')) {
          req.app.get('io').emit('holiday:changed', { action: 'deleted', id });
        }

        res.json({ success: true, message: 'Holiday removed.' });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to delete holiday.' });
      }
    });


    return router;
  })();
  api.use('/hr', hrRouter);

  const linksRouter = (() => {
    const router = express.Router();
    router.param('id', validRowId);

    // GET /api/links
    router.get('/', verifyToken, async (req, res) => {
      try {
        const links = MEMORY.links.slice().sort((a, b) => a.sort_order - b.sort_order || a.id - b.id);

        // Group links by group_name
        const groupMap = {};
        links.forEach(l => {
          const g = l.group_name || 'General';
          if (!groupMap[g]) groupMap[g] = [];
          groupMap[g].push(l);
        });

        const grouped = Object.keys(groupMap).map(g => ({
          group: g,
          items: groupMap[g]
        }));

        res.json({ success: true, data: grouped, flat: links });
      } catch (err) {
        console.error('Fetch links error:', err);
        res.status(500).json({ success: false, message: 'Failed to retrieve quick links.' });
      }
    });

    // POST /api/links (Admin only)
    router.post('/', verifyToken, requireAdmin, async (req, res) => {
      try {
        const { group_name, title, subtext, url, sort_order } = req.body;
        const order = sort_order == null ? 1 : Number(sort_order);
        if (!validText(group_name, 60) || !validText(title, 100) ||
            !validHttpUrl(url) || (subtext != null && !validText(subtext, 200, true)) ||
            !Number.isInteger(order) || order < 0 || order > 1000000) {
          return res.status(400).json({ success: false, message: 'Invalid quick link details.' });
        }

        const newLink = {
          id: nextId(MEMORY.links),
          group_name: group_name.trim(),
          title: title.trim(),
          subtext: (subtext || '').trim(),
          url: url.trim(),
          sort_order: order
        };
        MEMORY.links.push(newLink);

        if (req.app.get('io')) {
          req.app.get('io').emit('link:changed', { action: 'created', link: newLink });
        }

        res.status(201).json({ success: true, message: 'Quick link added successfully.', data: newLink });
      } catch (err) {
        console.error('Add link error:', err);
        res.status(500).json({ success: false, message: 'Failed to add quick link.' });
      }
    });

    // PUT /api/links/:id (Admin only)
    router.put('/:id', verifyToken, requireAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const { group_name, title, subtext, url, sort_order } = req.body;

        const order = sort_order == null ? 1 : Number(sort_order);
        if (!validText(group_name, 60) || !validText(title, 100) ||
            !validHttpUrl(url) || (subtext != null && !validText(subtext, 200, true)) ||
            !Number.isInteger(order) || order < 0 || order > 1000000) {
          return res.status(400).json({ success: false, message: 'Invalid quick link details.' });
        }

        const link = MEMORY.links.find((item) => String(item.id) === String(id));
        if (!link) return res.status(404).json({ success: false, message: 'Quick link not found.' });
        Object.assign(link, { group_name: group_name.trim(), title: title.trim(), subtext: (subtext || '').trim(), url: url.trim(), sort_order: order });

        if (req.app.get('io')) {
          req.app.get('io').emit('link:changed', { action: 'updated', link });
        }

        res.json({ success: true, message: 'Quick link updated successfully.', data: link });
      } catch (err) {
        console.error('Update link error:', err);
        res.status(500).json({ success: false, message: 'Failed to update quick link.' });
      }
    });

    // DELETE /api/links/:id (Admin only)
    router.delete('/:id', verifyToken, requireAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const index = MEMORY.links.findIndex((item) => String(item.id) === String(id));
        if (index < 0) return res.status(404).json({ success: false, message: 'Quick link not found.' });
        MEMORY.links.splice(index, 1);

        if (req.app.get('io')) {
          req.app.get('io').emit('link:changed', { action: 'deleted', id });
        }

        res.json({ success: true, message: 'Quick link deleted.' });
      } catch (err) {
        console.error('Delete link error:', err);
        res.status(500).json({ success: false, message: 'Failed to delete quick link.' });
      }
    });


    return router;
  })();
  api.use('/links', linksRouter);
  return api;
};
