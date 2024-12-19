#ifndef XBOX_ANALYZER_H
#define XBOX_ANALYZER_H

#include <string>
#include <vector>
#include "renderware.h" // Include Renderware definitions

class XboxAnalyzer {
public:
    XboxAnalyzer(const std::string& gamePath);
    bool loadGameFiles();
    std::vector<Renderware::Model> extractModels();
    std::vector<Renderware::Texture> extractTextures();

private:
    std::string gamePath;
};

#endif // XBOX_ANALYZER_H
