using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Primitives;

namespace Com.Bayoomed.TelematikFederation;

/// <summary>
///     This is needed to be able to provide themes via kubernetes configmap.
///     Unfortunately ASP .NET doesnt handle symlinks correctly so here is the cheat code...
/// </summary>
public class SymLinkFileProvider(string root) : IFileProvider
{
    private readonly PhysicalFileProvider _fileProvider = new(root);

    public IDirectoryContents GetDirectoryContents(string subpath)
    {
        return _fileProvider.GetDirectoryContents(subpath);
    }

    public IFileInfo GetFileInfo(string subpath)
    {
        return new SymLinkFileInfo(_fileProvider.GetFileInfo(subpath));
    }

    public IChangeToken Watch(string filter)
    {
        return _fileProvider.Watch(filter);
    }
}

/// <summary>
///     Magic is here. Correcting the length and forcing read from MemoryStream
/// </summary>
public class SymLinkFileInfo(IFileInfo info) : IFileInfo
{
    public Stream CreateReadStream()
    {
        return new MemoryStream(File.ReadAllBytes(info.PhysicalPath!));
    }

    public bool Exists { get; } = info.Exists;
    public long Length => File.ReadAllBytes(info.PhysicalPath!).Length;
    public string? PhysicalPath => null;
    public string Name  => info.Name;
    public DateTimeOffset LastModified  => info.LastModified;
    public bool IsDirectory => info.IsDirectory;
}