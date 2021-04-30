#include "pch.h"
#include "AuditCommon.h"

std::string queryAsString(Query q) {
  std::string s;
  return (s + std::asctime(&q.time) + " USER: " + std::to_string(q.user_id) + " ON PATIENT: " + 
    std::to_string(q.patient_id) + " ACTION: " + q.type);
}

void printQuery(Query q) {
  std::cout << std::asctime(&q.time) << " USER: " << q.user_id << " ON PATIENT: " << q.patient_id << " ACTION: " << q.type << std::endl; 
} 
